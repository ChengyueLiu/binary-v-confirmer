import os
from typing import List

import torch
from loguru import logger
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForSequenceClassification

from bintools.general.file_tool import load_from_json_file
from main.extractors.function_feature_extractor import extract_src_feature_for_specific_function
from main.interface import DataItemForFunctionConfirmModel, BinFunctionFeature, PossibleBinFunction, \
    CauseFunction
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_model_input
from main.models.function_confirm_model.dataset_and_data_provider import create_dataset_from_model_input
import torch.nn.functional as F


class FunctionFinder:
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

    def _preprocess_data(self, src_file_path,
                         cause_function_name,
                         binary_file_abs_path) -> (List[DataItemForFunctionConfirmModel], DataLoader):

        # step 1 提取源代码特征
        logger.info(f"Extracting feature for {src_file_path}")
        src_function_feature = extract_src_feature_for_specific_function(file_path=src_file_path,
                                                                         vul_function_name=cause_function_name)
        if src_function_feature is None:
            logger.error(f"Can't find function {cause_function_name} in {src_file_path}")
            return None, None
        logger.info(f"Feature extracted for {src_file_path}")

        # step 2 提取二进制文件特征
        logger.info(f"Extracting feature for {binary_file_abs_path}")
        # TODO linux下使用IDA Pro提取特征？
        # bin_function_features = extract_bin_feature(binary_file_abs_path)
        # ---------- 临时使用已经提取好的特征，以下是临时代码 ----------
        bin_file_name = os.path.basename(binary_file_abs_path)
        if bin_file_name == "openssl":
            IDA_PRO_OUTPUT_PATH = r"TestCases/model_train/model_1/test_data/ida_pro_results/openssl.json"
        elif bin_file_name == "libcrypto.so.3":
            IDA_PRO_OUTPUT_PATH = r"TestCases/model_train/model_1/test_data/ida_pro_results/libcrypto.json"
        elif bin_file_name == "libssl.so.3":
            IDA_PRO_OUTPUT_PATH = r"TestCases/model_train/model_1/test_data/ida_pro_results/libssl.json"
        results = load_from_json_file(IDA_PRO_OUTPUT_PATH)
        # 转换成外部的数据结构
        bin_function_features: List[BinFunctionFeature] = [BinFunctionFeature.init_from_dict(data=json_item)
                                                           for json_item in results]
        logger.info(f"{len(bin_function_features)} features extracted for {binary_file_abs_path}")
        # ---------- 以上是临时代码 ----------

        # step 3 使用模型遍历比较源代码函数和二进制文件函数
        # convert data
        data_items = convert_function_feature_to_model_input(src_function_feature, bin_function_features)
        dataset = create_dataset_from_model_input(data_items, self.tokenizer, max_len=512)
        dataloader = DataLoader(dataset, batch_size=self.batch_size, shuffle=False)

        return data_items, dataloader

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

    def find_similar_bin_functions(self, src_file_path,
                                   function_name,
                                   binary_file_abs_path: str):
        """
        输入一个源代码函数代码，和一个二进制文件，返回二进制文件中与源代码函数相似的汇编函数
            step 1: 提取源代码, 二进制文件特征
            step 2: 使用模型预测
            step 3: 输出结果
                1. 预测label为1的函数
                2.

        """
        # 预处理数据
        data_items, dataloader = self._preprocess_data(src_file_path,
                                                       function_name,
                                                       binary_file_abs_path)
        # 正规化处理的源代码
        normalized_src_codes = data_items[0].src_codes

        # 预测
        predictions = self._predict(dataloader)

        # 输出结果
        possible_bin_functions: List[PossibleBinFunction] = []
        for data_item, (pred, prob) in zip(data_items, predictions):
            if pred.item() == 1:
                possible_bin_function = PossibleBinFunction(
                    function_name=data_item.bin_function_name,
                    match_possibility=prob.item(),
                    asm_codes=data_item.asm_codes,
                )
                possible_bin_functions.append(possible_bin_function)
        possible_bin_functions.sort(key=lambda x: x.match_possibility, reverse=True)

        return normalized_src_codes, len(predictions), possible_bin_functions
