import copy
import random
from typing import List

from bintools.general.file_tool import save_to_json_file
from main.interface import FunctionFeature, DataItemForFunctionConfirmModel, SrcFunctionFeature, BinFunctionFeature

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


def generate_data_items(function_features: List[FunctionFeature], negative_ratio: int = 3):
    # positive examples
    positive_train_data_items = [DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1)
                                 for ff in function_features]

    # negative examples
    wrong_match_function_features = []
    for i, function_feature in enumerate(function_features):
        sample_function_features = random.sample(function_features, negative_ratio)
        for sample_function_feature in sample_function_features:
            if sample_function_feature != function_feature:
                wrong_match_function_feature = copy.deepcopy(function_feature)
                wrong_match_function_feature.bin_function_feature = sample_function_feature.bin_function_feature
                wrong_match_function_features.append(wrong_match_function_feature)
    negative_train_data_items = [DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=0) for ff in
                                 wrong_match_function_features]

    train_data_json = [item.custom_serialize() for item in positive_train_data_items + negative_train_data_items]
    return train_data_json


def convert_function_feature_to_train_data(function_feature_path: str,
                                           train_data_items_save_path: str,
                                           val_data_items_save_path: str,
                                           test_data_items_save_path: str,
                                           negative_ratio: int = 3):
    """
    把匹配的源代码函数和二进制函数特征转换成训练数据，同时生成负样本，并保存到指定路径

    :param function_feature_path:
    :param save_path:
    :param negative_ratio:
    :return:
    """
    function_features = FunctionFeature.init_from_json_file(function_feature_path)

    train_function_features, val_function_features, test_function_features = split_dataset(function_features)

    train_data_items = generate_data_items(train_function_features, negative_ratio)
    save_to_json_file(train_data_items, train_data_items_save_path)

    val_data_items = generate_data_items(val_function_features, negative_ratio)
    save_to_json_file(val_data_items, val_data_items_save_path)

    test_data_items = generate_data_items(test_function_features, negative_ratio)
    save_to_json_file(test_data_items, test_data_items_save_path)


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
