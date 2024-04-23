from typing import List

import torch
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import AutoTokenizer, RobertaForQuestionAnswering

from main.interface import DataItemForCodeSnippetPositioningModel
from main.models.code_snippet_positioning_model.dataset_and_data_provider import create_dataset_from_model_input
import torch.nn.functional as F


class SnippetPositioner:

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

    def create_dataloader(self, data_items: List[DataItemForCodeSnippetPositioningModel]):
        # create dataset
        dataset = create_dataset_from_model_input(data_items, self.tokenizer, max_len=512)
        # create dataloader
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        return dataloader

    def _predict(self, data_loader: DataLoader, predict_start=True):
        predicted_answers = []
        confidence_scores = []
        for batch in tqdm(data_loader, desc=f"locate patch(batch_size: {self.batch_size}):"):
            # 转移到设备
            batch_input_ids = batch['input_ids'].to(self.device)
            batch_attention_mask = batch['attention_mask'].to(self.device)

            # 批量预测
            with torch.no_grad():
                outputs = self.model(batch_input_ids, attention_mask=batch_attention_mask)

            # 计算每个token的概率
            start_probs = F.softmax(outputs.start_logits, dim=1)
            end_probs = F.softmax(outputs.end_logits, dim=1)

            # 获取最可能的答案的token的索引及其概率
            predict_answer_tokens_start_indices = start_probs.argmax(dim=1)
            predict_answer_tokens_end_indices = end_probs.argmax(dim=1)
            max_start_probs = start_probs.max(dim=1)[0]  # 获取最大概率
            max_end_probs = end_probs.max(dim=1)[0]  # 获取最大概率

            for input_ids, predict_answer_tokens_start_index, predict_answer_tokens_end_index, start_prob, end_prob in zip(
                    batch_input_ids, predict_answer_tokens_start_indices, predict_answer_tokens_end_indices,
                    max_start_probs, max_end_probs):
                # 获取预测的tokens
                answer_token_start_index = predict_answer_tokens_start_index.item()
                answer_token_end_index = predict_answer_tokens_end_index.item()
                predict_answer_tokens = input_ids[answer_token_start_index: answer_token_end_index + 1]

                # 解码
                answer = self.tokenizer.decode(predict_answer_tokens, skip_special_tokens=True)
                predicted_answers.append(answer)
                # 计算平均置信度（开始和结束概率的平均）
                if predict_start:
                    confidence_scores.append(start_prob.item())
                else:
                    confidence_scores.append(end_prob.item())
        predictions = [(answer, prob) for answer, prob in zip(predicted_answers, confidence_scores)]
        return predictions

    def locate(self, data_items: List[DataItemForCodeSnippetPositioningModel]):
        data_loader = self.create_dataloader(data_items)

        # predict
        predictions = self._predict(data_loader)
        return predictions
