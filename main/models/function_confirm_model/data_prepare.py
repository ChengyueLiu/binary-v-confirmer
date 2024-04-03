import copy
import difflib
import random
import traceback
from typing import List

import rapidfuzz.fuzz
from loguru import logger
from tqdm import tqdm

from bintools.general.normalize import normalize_asm_code, normalize_src_lines, normalize_asm_lines
from bintools.general.file_tool import save_to_json_file
from bintools.general.src_tool import count_function_effective_lines
from main.interface import FunctionFeature, DataItemForFunctionConfirmModel, SrcFunctionFeature, BinFunctionFeature, \
    SpecialToken, TrainFunction
from setting.settings import ASM_CODE_NUM, SRC_CODE_NUM, MODEL_1_TRAIN_DATA_ASM_CODE_MIN_NUM
from rapidfuzz import fuzz
from rapidfuzz import process

"""
这个文件的作用就是生成 TrainDataItemForFunctionConfirmModel
"""


def shuffle_and_split(lst, ratios=(0.8, 0.1, 0.1)):
    random.shuffle(lst)
    total_count = len(lst)
    train_end = int(total_count * ratios[0])
    val_end = train_end + int(total_count * ratios[1])

    lst_1 = lst[:train_end]
    lst_2 = lst[train_end:val_end]
    lst_3 = lst[val_end:]

    return lst_1, lst_2, lst_3


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


def generate_data_items(function_features: List[FunctionFeature], negative_ratio: int = 1, similarity_threshold=0.9):
    all_train_data_items = []
    asm_text_dict = {" ".join(normalize_asm_lines(ff.bin_function_feature.asm_codes[:ASM_CODE_NUM])): ff
                     for ff in function_features}
    asm_text_list = list(asm_text_dict.keys())
    for i, ff in tqdm(enumerate(function_features), desc="Generate data items"):
        # 正例子
        positive_item = DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
        all_train_data_items.append(positive_item)

        # 打乱function_features列表以随机化选择负例过程
        # 创建一个除了当前元素之外的列表副本
        other_function_features = function_features[:i] + function_features[i + 1:]
        random.shuffle(other_function_features)  # 随机打乱列表

        # 计算相似度
        similarities = []
        count = 0
        original_normalized_asm_codes = this_normalize_asm_code(ff.bin_function_feature.asm_codes[:ASM_CODE_NUM])
        for other_ff in other_function_features:
            sample_normalized_asm_codes = this_normalize_asm_code(
                other_ff.bin_function_feature.asm_codes[:ASM_CODE_NUM])
            similarity = levenshtein_distance(original_normalized_asm_codes, sample_normalized_asm_codes)
            if similarity < similarity_threshold:
                similarities.append((similarity, other_ff))
                count += 1
            if count >= negative_ratio:
                break

        # 生成负例
        for _, sample_function_feature in similarities[:negative_ratio]:
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

    # 打乱并划分数据集
    train_function_features, val_function_features, test_function_features = shuffle_and_split(function_features)

    train_data_items = generate_data_items(train_function_features, negative_ratio, similarity_threshold)
    save_to_json_file(train_data_items, train_data_items_save_path)

    val_data_items = generate_data_items(val_function_features)
    save_to_json_file(val_data_items, val_data_items_save_path)

    test_data_items = generate_data_items(test_function_features)
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
        if ff.bin_function_feature.name == "png_do_read_interlace":
            print("debug")
        data_item = DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
        data_item.normalize()
        model_input.append(data_item)
    return model_input


def generate_data_items_from_train_functions(train_functions: List[TrainFunction],
                                             expected_negative_num=5,
                                             similarity_threshold=0.5) -> List[
    DataItemForFunctionConfirmModel]:
    # 生成positive数据
    positive_data_items = []
    for tf in tqdm(train_functions, desc="generating positive data items"):
        try:
            # 生成一个训练数据
            data_item = tf.generate_model_1_train_data_item()
            if data_item is None:
                continue
            # 至少10行有效源代码
            if tf.effective_src_line_num < 10:
                continue
            # 汇编代码数量至少是有效源代码数量的两倍
            if len(data_item.asm_codes) < 2 * tf.effective_src_line_num:
                continue
            positive_data_items.append(data_item)
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error(e)

    negative_data_items = []
    for pdi in tqdm(positive_data_items, desc="generating negative data items"):
        attempt_count = 0  # 添加尝试次数计数器
        negative_count = 0
        while attempt_count < 100:  # 限制最大尝试次数，避免无限循环
            attempt_count += 1
            another_pdi = positive_data_items[random.randint(0, len(positive_data_items) - 1)]
            similarity = cal_similarity(pdi, another_pdi)
            if similarity < similarity_threshold:
                negative_data_item = copy.deepcopy(pdi)
                negative_data_item.bin_function_name = another_pdi.bin_function_name
                negative_data_item.asm_codes = another_pdi.asm_codes
                negative_data_item.label = 0
                negative_data_items.append(negative_data_item)
                negative_count += 1
            if negative_count >= expected_negative_num:
                break
    all_data_items = positive_data_items + negative_data_items
    for i, item in enumerate(all_data_items):
        item.id = i
    return all_data_items


def cal_similarity(data_item_1, data_item_2):
    data_item_1_copy = copy.deepcopy(data_item_1)
    data_item_1_copy.normalize()
    t1 = data_item_1_copy.get_train_text("[SEP]").split("[SEP]")[1]

    another_pdi_copy = copy.deepcopy(data_item_2)
    another_pdi_copy.normalize()
    another_pdi_copy.src_codes = data_item_1_copy.src_codes
    t2 = another_pdi_copy.get_train_text("[SEP]").split("[SEP]")[1]

    if len(t1) > len(t2):
        length = len(t2)
    else:
        length = len(t1)

    similarity = difflib.SequenceMatcher(None, t1[:length], t2[:length]).ratio()

    return similarity
