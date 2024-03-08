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


if __name__ == '__main__':
    # debug_convert_function_feature_to_train_data()
    from transformers import RobertaTokenizer, RobertaForSequenceClassification

    # Load GraphCodeBERT tokenizer
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/graphcodebert-base')

    # Load GraphCodeBERT model for sequence classification
    # model = RobertaForSequenceClassification.from_pretrained('microsoft/graphcodebert-base')

    vocab = set(tokenizer.get_vocab().keys())
    print(len(vocab))

    for special_token in ["[SRC_CODE]", "[SRC_STR]", "[SRC_NUM]", "[BIN_CODE]", "[BIN_STR]", "[BIN_NUM]"]:
        print(special_token in vocab)
    print("[SRC_CODE]" in vocab)
