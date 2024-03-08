from bintools.general.file_tool import load_from_json_file, save_to_json_file
from main.interface import FunctionFeature, TrainDataItemForFunctionConfirmModel
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data


def debug_convert_function_feature_to_train_data():
    """
    调试提取特征的整个流程
    :return:
    """
    function_feature_path = r"TestCases/feature_extraction/function_features.json"
    save_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    convert_function_feature_to_train_data(function_feature_path, save_path)

    # data = load_from_json_file(function_feature_path)
    #
    # function_feature = FunctionFeature.init_from_dict(data[333])
    # train_data_item = TrainDataItemForModel1(function_feature)
    # save_to_json_file(train_data_item.custom_serialize(), save_path)


def train_model_1():
    """
    训练模型1
    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    data_file_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    run_train(data_file_path, epochs=3, batch_size=16)


if __name__ == '__main__':
    # debug_convert_function_feature_to_train_data()
    train_model_1()
