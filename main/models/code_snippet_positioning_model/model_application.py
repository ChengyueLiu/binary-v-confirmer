from typing import List

import torch
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import AutoTokenizer, RobertaForQuestionAnswering

from bintools.general.bin_tool import normalize_asm_code
from bintools.general.src_tool import remove_comments
from main.interface import DataItemForCodeSnippetPositioningModel, SpecialToken
from main.models.code_snippet_positioning_model.dataset_and_data_provider import create_dataset, \
    CodeSnippetPositioningDataset


class CodeSnippetPositioner:

    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self):
        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = AutoTokenizer.from_pretrained(self.model_name, use_fast=True)
        for special_token in DataItemForCodeSnippetPositioningModel.get_special_tokens():
            tokenizer.add_tokens(special_token)

        # model
        model = RobertaForQuestionAnswering.from_pretrained(self.model_name)
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
        # step 1: 输入转换为DataItemForCodeSnippetPositioningModel
        data_item = DataItemForCodeSnippetPositioningModel(function_name=vul_function_name,
                                                           src_codes=src_codes,
                                                           asm_codes=asm_codes,
                                                           answer_start_index=0,
                                                           answer_end_index=0,
                                                           normalized=False)
        # TODO 这个地方要根据具体的参数来处理，因为输入的src_code一般会超过5行，而输入的asm_code一般也会超过50行。但是预训练的模型，输入的长度是有限制的。一般接受5行源代码和50行汇编代码
        train_data_items = [data_item]

        # step 2: 创建dataset
        questions = []
        contexts = []
        answer_start_indexes = []
        answer_end_indexes = []
        for train_data_item in train_data_items:
            questions.append(train_data_item.get_question_text())
            contexts.append(train_data_item.get_context_text())
            answer_start_index, answer_end_index = train_data_item.get_answer_position()
            answer_start_indexes.append(answer_start_index)
            answer_end_indexes.append(answer_end_index)

        print("原始数据数量: ", len(questions))
        dataset = CodeSnippetPositioningDataset(questions,
                                                contexts,
                                                answer_start_indexes,
                                                answer_end_indexes,
                                                self.tokenizer)

        # step 3: 创建dataloader
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)

        return dataloader

    def _predict(self, dataloader: DataLoader):
        predicted_answers = []
        for batch in tqdm(dataloader, desc="positioning code snippet ..."):
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

                predicted_answers.append(answer)
        return predicted_answers

    def position(self, vul_function_name, src_codes: List[str], asm_codes: List[str]):
        """
        输入漏洞函数代码片段，输出代码片段代汇编代码函数中的可能的位置
        steps：
            1. 预处理数据，主要是正规化处理源代码和汇编代码
            2. 使用模型预测


        :param src_codes: 源代码中提取到的代码片段，代表了漏洞函数中的关键patch代码
        :param asm_codes: 使用IDA Pro提取到的汇编代码片段，代表了第一个模型找到的可能的漏洞函数
        :return:
        """
        # 预处理数据
        dataloader = self._preprocess_data(vul_function_name, src_codes, asm_codes)

        # 使用模型预测
        predicted_answers = self._predict(dataloader)

        print("predicted_answers: ", predicted_answers)
        print("expected_answers: ", " ".join(asm_codes[17:27]))