from typing import List

import torch
from loguru import logger
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForSequenceClassification

from bintools.general.file_tool import check_file_path
from main.extractors.function_feature_extractor import extract_bin_feature, extract_src_feature_for_specific_function
from main.interface import DataItemForFunctionConfirmModel, BinFunctionFeature
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_model_input
from main.models.function_confirm_model.dataset_and_data_provider import create_dataset_from_model_input
import torch.nn.functional as F


class VulFunctionFinder:
    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self) -> (torch.device, RobertaTokenizer, RobertaForSequenceClassification):

        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
            tokenizer.add_tokens(special_token)

        # model
        model = RobertaForSequenceClassification.from_pretrained(self.model_name, num_labels=self.num_labels)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def _preprocess_data(self, src_file_path, vul_function_name, binary_file_abs_path) -> (
            DataLoader, List[BinFunctionFeature]):
        src_file_path = check_file_path(src_file_path)
        binary_file_abs_path = check_file_path(binary_file_abs_path)

        # step 1 提取源代码特征
        logger.info(f"Extracting feature for {src_file_path}")
        src_function_feature = extract_src_feature_for_specific_function(file_path=src_file_path,
                                                                         vul_function_name=vul_function_name)
        if src_function_feature is None:
            logger.error(f"Can't find function {vul_function_name} in {src_file_path}")
            return None

        logger.info(f"Feature extracted for {src_file_path}")
        # step 2 提取二进制文件特征
        logger.info(f"Extracting feature for {binary_file_abs_path}")
        bin_function_features = extract_bin_feature(binary_file_abs_path)
        logger.info(f"{len(bin_function_features)} features extracted for {binary_file_abs_path}")

        # step 3 使用模型遍历比较源代码函数和二进制文件函数

        # convert data
        data_items = convert_function_feature_to_model_input(src_function_feature, bin_function_features)
        dataset = create_dataset_from_model_input(data_items, self.tokenizer, max_len=512)
        dataloader = DataLoader(dataset, batch_size=16, shuffle=False)

        return dataloader, bin_function_features

    def _predict(self, dataloader):
        """

        :param dataloader:
        :return: [(pred, prob), ...]
        """
        # predict
        predictions = []
        for batch in tqdm(dataloader, desc="confirming functions ..."):
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
                predictions.append((pred, prob))
        return predictions

    def find_similar_functions(self, src_file_path: str, vul_function_name: str, binary_file_abs_path: str) -> List[
        BinFunctionFeature]:
        """
        输入一个源代码函数代码，和一个二进制文件，返回二进制文件中与源代码函数相似的汇编函数

        """
        # 预处理数据
        dataloader, bin_function_features = self._preprocess_data(src_file_path, vul_function_name,
                                                                  binary_file_abs_path)

        # 预测
        predictions = self._predict(dataloader)

        # 输出结果
        similar_functions = []
        for bin_function_feature, (pred, prob) in zip(bin_function_features, predictions):
            if pred.item() == 1:
                print(bin_function_feature.function_name, pred.item(), prob.item())
                similar_functions.append(bin_function_feature)

        return similar_functions
