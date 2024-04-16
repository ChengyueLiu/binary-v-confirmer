import copy
import difflib
import multiprocessing
import random
import traceback
from typing import List, Tuple

import rapidfuzz.fuzz
from loguru import logger
from tqdm import tqdm

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.normalize import normalize_asm_code, normalize_src_lines, normalize_asm_lines
from bintools.general.file_tool import save_to_json_file
from bintools.general.src_tool import count_function_effective_lines, analyze_src_codes
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
        data_item = DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
        data_item.normalize()
        model_input.append(data_item)
    return model_input

def generate_positive_data_item(tf: TrainFunction) -> Tuple[DataItemForFunctionConfirmModel, str]:
    try:
        data_item = tf.generate_model_1_train_data_item()
        if data_item is None or tf.effective_src_line_num < 10 or len(data_item.asm_codes) < 2 * tf.effective_src_line_num:
            return None
        data_item_copy = generate_data_item_for_cal(data_item)
        return (data_item, " ".join(data_item_copy.asm_codes[:30]))
    except Exception as e:
        return None

def generate_negative_data_items(pdi, another_pdi):
    # pdi, another_pdi = args
    pdi_copy = generate_data_item_for_cal(pdi)
    text = " ".join(pdi_copy.asm_codes[:30])
    negative_data_items = []

    # 使用随机选择的另一个pdi，作为负例
    negative_data_item = copy.deepcopy(pdi)
    negative_data_item.bin_function_name = another_pdi.bin_function_name
    negative_data_item.asm_codes = another_pdi.asm_codes
    negative_data_item.label = 0
    negative_data_item_copy = generate_data_item_for_cal(negative_data_item)
    negative_data_item.similarity = fuzz.ratio(text, " ".join(negative_data_item_copy.asm_codes[:30]))
    negative_data_items.append(negative_data_item)

    # 修改当前正例的汇编代码，形成负例
    modified_pdi = copy.deepcopy(pdi)
    # 随机位置的汇编码复制一份
    modified_pdi.asm_codes = modify_asm_codes(pdi.asm_codes)
    modified_pdi.label = 0
    negative_data_item_copy = generate_data_item_for_cal(modified_pdi)
    modified_pdi.similarity = fuzz.ratio(text, " ".join(negative_data_item_copy.asm_codes[:30]))
    if 80 < modified_pdi.similarity < 98:
        negative_data_items.append(modified_pdi)

    return negative_data_items
def generate_data_items_from_train_functions(train_functions: List[TrainFunction],
                                             expected_negative_num=5,
                                             similarity_threshold=0.5) -> List[
    DataItemForFunctionConfirmModel]:
    positive_data_items = []
    positive_text_list = []

    # 使用多进程生成正例数据
    with multiprocessing.Pool(processes=multiprocessing.cpu_count()) as pool:
        # 使用imap代替map，以tqdm直接封装结果，显示进度条
        results = pool.imap_unordered(generate_positive_data_item, train_functions)
        for result in tqdm(results, total=len(train_functions), desc="Generating positive data items"):
            if result:
                data_item, text = result
                positive_data_items.append(data_item)
                positive_text_list.append(text)

    # Define the number of processes
    num_processes = multiprocessing.cpu_count()

    # Initialize a multiprocessing pool
    pool = multiprocessing.Pool(processes=num_processes)

    # Use tqdm for progress bar
    with tqdm(total=len(positive_data_items), desc="Generating negative data items") as pbar:
        results = []
        for pdi in positive_data_items:
            # 随机选择另一个pdi
            another_pdi = positive_data_items[random.randint(0, len(positive_data_items) - 1)]
            # 异步调用，传递pdi和另一个随机选择的pdi给处理函数
            arg = (pdi, another_pdi)
            result = pool.apply_async(generate_negative_data_items, args=arg)
            results.append(result)

        all_negative_data_items = []
        for result in results:
            negative_data_items = result.get()
            all_negative_data_items.extend(negative_data_items)
            pbar.update(1)

    pool.close()
    pool.join()

    print(len(positive_data_items), len(all_negative_data_items))
    all_data_items = positive_data_items + all_negative_data_items
    for i, item in enumerate(all_data_items):
        item.id = i
    return all_data_items


def modify_asm_codes(original_asm_codes):

    asm_codes = copy.deepcopy(original_asm_codes[:30])
    # 确保输入列表的长度足够进行操作
    if len(asm_codes) < 3:
        raise ValueError("The input list must contain at least 3 elements.")

    # 随机选择三个位置复制并插入到位置后面
    for _ in range(3):
        index = random.randint(0, len(asm_codes) - 1)
        asm_codes.insert(index + 1, asm_codes[index])

    # 由于列表长度已改变，确保删除操作的索引不会越界
    if len(asm_codes) < 6:
        raise ValueError("After insertions, the list is too short for deletions.")

    # 随机选择三个位置删除
    for _ in range(3):
        # 每次删除后列表长度减一，故随机范围也相应减小
        index = random.randint(0, len(asm_codes) - 1)
        del asm_codes[index]

    # 随机选择两个位置互换
    index1, index2 = random.sample(range(len(asm_codes)), 2)
    asm_codes[index1], asm_codes[index2] = asm_codes[index2], asm_codes[index1]

    original_asm_codes[:30] = asm_codes
    return original_asm_codes

def cal_similarity(data_item_1, data_item_2):
    data_item_1_copy = generate_data_item_for_cal(data_item_1)
    t1 = data_item_1_copy.get_train_text("[SEP]").split("[SEP]")[1]

    data_item_2_copy = generate_data_item_for_cal(data_item_2)
    data_item_2_copy.src_codes = data_item_1_copy.src_codes
    t2 = data_item_2_copy.get_train_text("[SEP]").split("[SEP]")[1]

    if len(t1) > len(t2):
        length = len(t2)
    else:
        length = len(t1)

    similarity = difflib.SequenceMatcher(None, t1[:length], t2[:length]).ratio()
    return similarity


def generate_data_item_for_cal(data_item):
    data_item_copy = copy.deepcopy(data_item)
    data_item_copy.normalize()
    src_body_start_index, src_param_count = analyze_src_codes(data_item_copy.src_codes)
    bin_body_start_index, bin_param_count = analyze_asm_codes(data_item_copy.asm_codes)
    data_item_copy.src_codes = data_item_copy.src_codes[src_body_start_index:]
    data_item_copy.asm_codes = data_item_copy.asm_codes[bin_body_start_index:]

    return data_item_copy
