from typing import List

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForMultipleChoice

from main.interface import DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.dataset_and_data_provider import CodeSnippetConfirmDataset


class SnippetChoicer:
    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self) -> (torch.device, RobertaTokenizer, RobertaForMultipleChoice):

        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        for special_token in DataItemForCodeSnippetConfirmModelMC.get_special_tokens():
            tokenizer.add_tokens(special_token)

        # model
        model = RobertaForMultipleChoice.from_pretrained(self.model_name, num_labels=self.num_labels)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def _preprocess_data(self, asm_code_texts: List[str], vul_src_code_text: str, patch_src_code_text: str):
        vul_src_code_texts = [vul_src_code_text] * len(asm_code_texts)
        patch_src_code_texts = [patch_src_code_text] * len(asm_code_texts)
        dataset = CodeSnippetConfirmDataset(questions=asm_code_texts,
                                            choice_1_list=vul_src_code_texts,
                                            choice_2_list=patch_src_code_texts,
                                            tokenizer=self.tokenizer,
                                            shuffle_choices=False)
        train_loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        return train_loader

    def _predict(self, dataloader):
        predictions = []
        for batch in dataloader:
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            with torch.no_grad():
                outputs = self.model(input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            probabilities = F.softmax(logits, dim=-1)

            # 对每个问题处理，提取每个选项的信息
            for i in range(logits.size(0)):  # 遍历batch中的每个样本，即每个问题
                question_predictions = []
                for option_index in range(logits.size(1)):  # 遍历该问题的每个选项
                    score = round(logits[i, option_index].item(), 4)  # 该选项的得分
                    prob = round(probabilities[i, option_index].item(), 4)  # 该选项的概率
                    question_predictions.append((option_index, score, prob))
                predictions.append(question_predictions)

        return predictions

    def choice(self, asm_code_texts: List[str], vul_src_code_text: str, patch_src_code_text: str):
        """
        输入一个源代码函数代码，和一个二进制文件，返回二进制文件中与源代码函数相似的汇编函数

        """
        # 预处理数据
        dataloader = self._preprocess_data(asm_code_texts, vul_src_code_text, patch_src_code_text)

        # 预测
        predictions = self._predict(dataloader)
        return predictions
