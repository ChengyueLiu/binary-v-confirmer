from typing import List

import torch
from loguru import logger
from torch.utils.data import DataLoader
from transformers import AutoTokenizer, AutoConfig, BigBirdForQuestionAnswering

from main.interface import DataItemForCodeSnippetPositioningModel
from main.models.code_snippet_positioning_model_bigbird.dataset_and_data_provider import CodeSnippetPositioningDataset


def split_list_by_sliding_window(input_list, window_length=50, step=20):
    # 初始化一个空列表来存放所有窗口
    windows = []

    # 如果输入列表长度小于等于窗口长度，直接返回
    if len(input_list) <= window_length:
        return [input_list]

    # 滑动窗口
    window_end = window_length
    while True:
        windows.append(input_list[window_end - window_length:window_end])
        if window_end + step > len(input_list):
            break
        window_end += step

    # 如果最后一个窗口的长度不足，补齐
    if window_end < len(input_list):
        windows.append(input_list[-window_length:])

    return windows


def remove_subsets(str_list):
    # 按字符串长度排序，这样我们可以先处理短字符串
    sorted_str_list = sorted(str_list, key=len)
    result = []

    for i in range(len(sorted_str_list)):
        subset_found = False
        for j in range(i + 1, len(sorted_str_list)):
            # 如果当前字符串是后面任一字符串的子集，则标记它，不再添加到结果中
            if sorted_str_list[i] in sorted_str_list[j]:
                subset_found = True
                break
        # 如果当前字符串不是任何字符串的子集，则添加到结果列表中
        if not subset_found:
            result.append(sorted_str_list[i])

    return result


class SnippetPositioner_BB:

    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16,windows_length=200,step=80):
        self.model_name = 'google/bigbird-roberta-base'
        self.num_labels = 2
        self.window_length = windows_length
        self.step = step
        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self):
        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        # tokenizer 和 model 需要根据 BigBird 进行修改
        config = AutoConfig.from_pretrained(self.model_name, attention_type="block_sparse", block_size=64,
                                            num_random_blocks=3)
        tokenizer = AutoTokenizer.from_pretrained(self.model_name, config=config)
        for special_token in DataItemForCodeSnippetPositioningModel.get_special_tokens():
            tokenizer.add_tokens(special_token)

        model = BigBirdForQuestionAnswering.from_pretrained(self.model_name, config=config)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def _preprocess_data(self, vul_function_name: str, src_codes: List[str], asm_codes: List[str]):
        """

        :param vul_function_name:
        :param src_codes:
        :param asm_codes:
        :return:
        """
        asm_codes_window_list = split_list_by_sliding_window(asm_codes, window_length=self.window_length, step=self.step)
        data_items = []
        # step 1: 输入转换为DataItemForCodeSnippetPositioningModel
        for i, asm_codes_window in enumerate(asm_codes_window_list):
            data_item = DataItemForCodeSnippetPositioningModel(function_name=vul_function_name,
                                                               src_codes=src_codes,
                                                               asm_codes=asm_codes_window,
                                                               answer_start_index=0,
                                                               answer_end_index=0)
            data_item.normalize_src_codes()
            data_items.append(data_item)

        # step 2: 创建dataset
        questions = []
        contexts = []
        answer_start_indexes = []
        answer_end_indexes = []
        for data_item in data_items:
            questions.append(data_item.get_question_text())
            contexts.append(data_item.get_context_text())
            answer_start_index, answer_end_index = data_item.get_answer_position()
            if answer_end_index < answer_start_index:
                logger.warning(f"answer_end_index < answer_start_index: {answer_end_index} < {answer_start_index}")
            answer_start_indexes.append(answer_start_index)
            answer_end_indexes.append(answer_end_index)

        # print("原始数据数量: ", len(questions))
        dataset = CodeSnippetPositioningDataset(questions,
                                                contexts,
                                                answer_start_indexes,
                                                answer_end_indexes,
                                                self.tokenizer)

        # step 3: 创建dataloader
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)

        return dataloader, questions[0]

    def _predict(self, dataloader: DataLoader):
        predicted_answers = []
        for batch in dataloader:
            # 转移到设备
            batch_input_ids = batch['input_ids'].to(self.device)
            batch_attention_mask = batch['attention_mask'].to(self.device)

            # 批量预测
            with torch.no_grad():
                outputs = self.model(batch_input_ids, attention_mask=batch_attention_mask)

            # 获取最可能的答案的token的索引
            predict_answer_tokens_start_indices = outputs.start_logits.argmax(dim=1)
            predict_answer_tokens_end_indices = outputs.end_logits.argmax(dim=1)

            for input_ids, predict_answer_tokens_start_index, predict_answer_tokens_end_index in zip(batch_input_ids,
                                                                                                     predict_answer_tokens_start_indices,
                                                                                                     predict_answer_tokens_end_indices):
                # 获取预测的tokens
                answer_token_start_index = predict_answer_tokens_start_index.item()
                answer_token_end_index = predict_answer_tokens_end_index.item()
                predict_answer_tokens = input_ids[answer_token_start_index: answer_token_end_index + 1]

                # 解码
                answer = self.tokenizer.decode(predict_answer_tokens, skip_special_tokens=True)
                if answer:
                    predicted_answers.append(answer)
        # 移除子集
        predicted_answers = remove_subsets(predicted_answers)
        return predicted_answers

    def position(self, vul_function_name, src_codes: List[str], asm_codes: List[str]):
        """
        输入漏洞函数代码片段，输出代码片段代汇编代码函数中的可能的位置
        steps：
            1. 预处理数据，主要是正规化处理源代码和汇编代码
            2. 使用模型预测


        :param analysis:
        :param vul_function_name:
        :param src_codes: 源代码中提取到的代码片段，代表了漏洞函数中的关键patch代码
        :param asm_codes: 使用IDA Pro提取到的汇编代码片段，代表了第一个模型找到的可能的漏洞函数
        :return:
        """
        # 预处理数据
        dataloader, question = self._preprocess_data(vul_function_name, src_codes, asm_codes)

        # 使用模型预测
        predicted_answers = self._predict(dataloader)

        return question, predicted_answers
