from typing import List

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForMultipleChoice

from main.interface import DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.dataset_and_data_provider import CodeSnippetConfirmDataset, \
    create_dataset_from_model_input


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

    def create_dataloader(self, data_items):
        # create dataset
        dataset = create_dataset_from_model_input(data_items, self.tokenizer, max_len=512)
        # create dataloader
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        return dataloader

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
                most_prob = 0
                most_index = 0
                for option_index in range(logits.size(1)):  # 遍历该问题的每个选项
                    score = round(logits[i, option_index].item(), 4)  # 该选项的得分
                    prob = probabilities[i, option_index].item()  # 该选项的概率
                    if prob > most_prob:
                        most_prob = prob
                        most_index = option_index
                predictions.append((most_index, most_prob))

        return predictions

    def choice(self, data_items: List[DataItemForCodeSnippetConfirmModelMC]):
        data_loader = self.create_dataloader(data_items)

        # predict
        predictions = self._predict(data_loader)
        return predictions
