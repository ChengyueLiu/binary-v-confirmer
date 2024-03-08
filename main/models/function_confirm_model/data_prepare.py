from bintools.general.file_tool import save_to_json_file
from main.interface import FunctionFeature, TrainDataItemForFunctionConfirmModel


def convert_function_feature_to_train_data(function_feature_path: str, save_path: str):
    function_features = FunctionFeature.init_from_json_file(function_feature_path)

    train_data_items = [TrainDataItemForFunctionConfirmModel(ff) for ff in function_features]

    train_data_json = [item.custom_serialize() for item in train_data_items]

    save_to_json_file(train_data_json, save_path)
