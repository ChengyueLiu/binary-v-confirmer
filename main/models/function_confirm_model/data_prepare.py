import copy
import random

from bintools.general.file_tool import save_to_json_file
from main.interface import FunctionFeature, TrainDataItemForFunctionConfirmModel


def convert_function_feature_to_train_data(function_feature_path: str, save_path: str, negative_ratio: int = 3):
    function_features = FunctionFeature.init_from_json_file(function_feature_path)

    # positive examples
    positive_train_data_items = [TrainDataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1) for ff in
                                 function_features]

    # negative examples
    wrong_match_function_features = []
    for i, function_feature in enumerate(function_features):
        sample_function_features = random.sample(function_features, negative_ratio)
        for sample_function_feature in sample_function_features:
            if sample_function_feature != function_feature:
                wrong_match_function_feature = copy.deepcopy(function_feature)
                wrong_match_function_feature.bin_function_feature = sample_function_feature.bin_function_feature
                wrong_match_function_features.append(wrong_match_function_feature)
    negative_train_data_items = [TrainDataItemForFunctionConfirmModel.init_from_function_feature(ff, label=0) for ff in
                                    wrong_match_function_features]


    train_data_json = [item.custom_serialize() for item in positive_train_data_items + negative_train_data_items]

    save_to_json_file(train_data_json, save_path)
