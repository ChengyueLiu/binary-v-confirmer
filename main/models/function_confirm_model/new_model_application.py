import os
from typing import List

import torch
from loguru import logger
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForSequenceClassification

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import count_function_effective_lines, analyze_src_codes
from main.extractors.function_feature_extractor import extract_src_feature_for_specific_function
from main.interface import DataItemForFunctionConfirmModel, BinFunctionFeature, PossibleBinFunction, \
    CauseFunction, SrcFunctionFeature, SpecialToken
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_model_input
from main.models.function_confirm_model.dataset_and_data_provider import create_dataset_from_model_input
import torch.nn.functional as F


class FunctionConfirmer():

    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_model()

    def _init_model(self) -> (torch.device, RobertaTokenizer, RobertaForSequenceClassification):

        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
            tokenizer.add_tokens(special_token)
        for frequent_token in SpecialToken.get_asm_frequent_tokens():
            tokenizer.add_tokens(frequent_token)
        # model
        model = RobertaForSequenceClassification.from_pretrained(self.model_name, num_labels=self.num_labels)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def create_dataloader(self, data_items: List[DataItemForFunctionConfirmModel]):
        # create dataset
        dataset = create_dataset_from_model_input(data_items, self.tokenizer, max_len=512)
        # create dataloader
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)
        return dataloader

    def _predict(self, dataloader):
        """

        :param dataloader:
        :return: [(pred, prob), ...]
        """
        # predict
        predictions = []
        for batch in tqdm(dataloader, desc=f"\tconfirming functions(batch_size: {self.batch_size}):"):
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            with torch.no_grad():
                outputs = self.model(input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            # 使用softmax计算概率
            probabilities = F.softmax(logits, dim=-1)

            # 找到每个样本的最大概率及其索引
            max_probs, preds = torch.max(probabilities, dim=-1)
            for pred, prob in zip(preds, max_probs):
                predictions.append((pred.item(), prob.item()))
        return predictions

    def confirm(self, data_items: List[DataItemForFunctionConfirmModel]):
        data_loader = self.create_dataloader(data_items)

        # predict
        predictions = self._predict(data_loader)

        return predictions
