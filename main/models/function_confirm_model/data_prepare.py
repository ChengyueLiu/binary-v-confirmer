import copy
import difflib
import random
from typing import List

import rapidfuzz.fuzz
from loguru import logger
from tqdm import tqdm

from bintools.general.normalize import normalize_asm_code, normalize_src_lines
from bintools.general.file_tool import save_to_json_file
from main.interface import FunctionFeature, DataItemForFunctionConfirmModel, SrcFunctionFeature, BinFunctionFeature, \
    SpecialToken
from setting.settings import ASM_CODE_NUM, SRC_CODE_NUM
from rapidfuzz import fuzz
from rapidfuzz import process
"""
这个文件的作用就是生成 TrainDataItemForFunctionConfirmModel
"""


def split_dataset(function_features: List[FunctionFeature], ratios=(0.8, 0.1, 0.1)):
    random.shuffle(function_features)
    total_count = len(function_features)
    train_end = int(total_count * ratios[0])
    val_end = train_end + int(total_count * ratios[1])

    train_set = function_features[:train_end]
    val_set = function_features[train_end:val_end]
    test_set = function_features[val_end:]

    return train_set, val_set, test_set


def this_normalize_asm_code(asm_codes):
    return [normalized_code for code in asm_codes
            if (normalized_code := normalize_asm_code(code,
                                                      reg_token=SpecialToken.ASM_REG.value,
                                                      num_token=SpecialToken.ASM_NUM.value,
                                                      jump_token=SpecialToken.ASM_JUMP.value,
                                                      loc_token=SpecialToken.ASM_LOC.value,
                                                      mem_token=SpecialToken.ASM_MEM.value))]


def levenshtein_distance(asm_codes_1: List[str], asm_codes_2: List[str]):
    s1 = " ".join(this_normalize_asm_code(asm_codes_1))
    s2 = " ".join(this_normalize_asm_code(asm_codes_2))

    return difflib.SequenceMatcher(None, s1, s2).ratio()


def generate_data_items(function_features: List[FunctionFeature], negative_ratio: int = 3,similarity_threshold = 0.1):
    all_train_data_items = []
    src_text_dict = {" ".join(normalize_src_lines(ff.src_function_features[0].original_lines[:SRC_CODE_NUM])):ff for ff in function_features}
    src_text_list = list(src_text_dict.keys())
    for i, ff in tqdm(enumerate(function_features), desc="Generate data items"):
        # 正例子
        positive_item = DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
        all_train_data_items.append(positive_item)

        # 计算相似度
        target_src_text = " ".join(normalize_src_lines(ff.src_function_features[0].original_lines)[:SRC_CODE_NUM])
        # 最相似的5个
        top_n_negative_num = negative_ratio // 2
        top_n_similar_texts = process.extract(target_src_text, src_text_list, scorer=fuzz.ratio, limit=top_n_negative_num+1)

        # 最不相似的5个
        count = negative_ratio - top_n_negative_num
        least_n_similar_texts = []
        for j,(other_ff_text,other_ff) in enumerate(src_text_dict.items()):
            if i==j:
                continue
            similarity = rapidfuzz.fuzz.ratio(target_src_text,other_ff_text)
            if similarity < similarity_threshold:
                least_n_similar_texts.append((other_ff_text,similarity,j))
                if count>=5:
                    break


        # 生成负例
        negative_similarities = top_n_similar_texts[1:] + least_n_similar_texts
        for text,similarity,index in negative_similarities:
            sample_function_feature = src_text_dict[text]
            wrong_match_function_feature = copy.deepcopy(ff)
            wrong_match_function_feature.bin_function_feature = sample_function_feature.bin_function_feature
            negative_item = DataItemForFunctionConfirmModel.init_from_function_feature(wrong_match_function_feature,
                                                                                       label=0)
            all_train_data_items.append(negative_item)

    # 给一个id ，方便调试
    for i, item in enumerate(all_train_data_items):
        item.id = i
    train_data_json = [item.custom_serialize() for item in all_train_data_items]
    return train_data_json


def convert_function_feature_to_train_data(function_feature_path: str,
                                           train_data_items_save_path: str,
                                           val_data_items_save_path: str,
                                           test_data_items_save_path: str,
                                           negative_ratio: int = 3,
                                           similarity_threshold=0.1):
    """
    把匹配的源代码函数和二进制函数特征转换成训练数据，同时生成负样本，并保存到指定路径

    :param function_feature_path:
    :param save_path:
    :param negative_ratio:
    :return:
    """
    function_features = FunctionFeature.init_from_json_file(function_feature_path)

    train_function_features, val_function_features, test_function_features = split_dataset(function_features)

    train_data_items = generate_data_items(train_function_features, negative_ratio,similarity_threshold)
    save_to_json_file(train_data_items, train_data_items_save_path)

    val_data_items = generate_data_items(val_function_features, negative_ratio,similarity_threshold)
    save_to_json_file(val_data_items, val_data_items_save_path)

    test_data_items = generate_data_items(test_function_features, negative_ratio,similarity_threshold)
    save_to_json_file(test_data_items, test_data_items_save_path)
    logger.info(
        f"Train data items: {len(train_data_items)}, Val data items: {len(val_data_items)}, Test data items: {len(test_data_items)}")


def convert_function_feature_to_model_input(src_function_feature: SrcFunctionFeature,
                                            bin_function_features: List[BinFunctionFeature]):
    """
    把源代码函数特征和每一个二进制函数特征转换成模型的输入格式
    :param src_function_feature:
    :param bin_function_features:
    :return:
    """
    function_features = []
    for bin_function_feature in bin_function_features:
        function_feature = FunctionFeature(function_name=src_function_feature.name,
                                           bin_function_feature=bin_function_feature,
                                           src_function_features=[src_function_feature])

        function_features.append(function_feature)

    model_input = []
    for ff in function_features:
        data_item = DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
        data_item.normalize()
        model_input.append(data_item)
    return model_input
