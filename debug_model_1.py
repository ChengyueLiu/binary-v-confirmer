import os
import subprocess

from loguru import logger
from tqdm import tqdm
from transformers import RobertaTokenizer

from bintools.general.file_tool import save_to_json_file, load_from_json_file
from main.interface import DataItemForFunctionConfirmModel, FunctionFeature
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data
from main.models.function_confirm_model.model_application import VulFunctionFinder
from setting.paths import IDA_PRO_PATH, IDA_PRO_SCRIPT_PATH


def debug_convert_function_feature_to_train_data():
    """
    调试提取特征的整个流程
    :return:
    """
    function_feature_path = r"TestCases/feature_extraction/function_features.json"
    save_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    convert_function_feature_to_train_data(function_feature_path, save_path, negative_ratio=3)

    # data = load_from_json_file(function_feature_path)
    #
    # function_feature = FunctionFeature.init_from_dict(data[333])
    # train_data_item = TrainDataItemForModel1(function_feature)
    # save_to_json_file(train_data_item.custom_serialize(), save_path)


def debug_model_application():
    """
    测试模型的应用

    :return:
    """

    # linux
    root_dir = r"/home/chengyue/projects/binary-v-confirmer/"
    batch_size = 64

    # windows
    # root_dir = r"C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer"
    # import os
    # os.environ["CUDA_VISIBLE_DEVICES"] = "0"
    # batch_size = 16

    test_data_dir = os.path.join(root_dir, "TestCases/model_train/model_1/test_data")
    # src file
    vul_function_file_path = os.path.join(test_data_dir, "p12_add.c")

    # vul function name
    vul_function_name = "*PKCS12_unpack_p7data"

    # binary file
    openssl = os.path.join(test_data_dir, "openssl")
    libcrypto = os.path.join(test_data_dir, "libcrypto.so.3")
    libssl = os.path.join(test_data_dir, "libssl.so.3")

    # model init
    model_save_path = os.path.join(root_dir, "model_weights.pth")

    vul_function_finder = VulFunctionFinder(
        model_save_path=model_save_path,
        batch_size=batch_size
    )
    similar_functions_dict = {}
    # 三个漏洞，三个二进制文件
    for binary in [openssl, libcrypto, libssl]:
        similar_functions_dict[binary] = binary_similar_functions_dict = {}
        for vul_function_name in ["*PKCS12_unpack_p7data", "*PKCS12_unpack_p7encdata", "*PKCS12_unpack_authsafes"]:
            logger.info(f"Finding similar functions for {vul_function_name} in {binary}")
            bin_function_num, similar_functions = vul_function_finder.find_similar_functions(
                src_file_path=vul_function_file_path,
                vul_function_name=vul_function_name,
                binary_file_abs_path=binary)

            binary_similar_functions_dict[vul_function_name] = {
                "vul_function_name": vul_function_name,
                "all_function_num": bin_function_num,
                "similar_function_num": len(similar_functions),
                "similar_functions": similar_functions
            }
    result_path = os.path.join(test_data_dir, "similar_functions.json")
    save_to_json_file(similar_functions_dict, result_path)
    logger.info(f"Result saved to {result_path}")
    logger.info(f"Done")


def train_model_1():
    """
    训练模型1, 这个不是一个调试函数，而是一个可用的训练函数

    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    data_file_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    run_train(data_file_path, epochs=3, batch_size=16)


def debug_token_length():
    function_features = FunctionFeature.init_from_json_file("TestCases/feature_extraction/function_features.json")

    # positive examples
    positive_train_data_items = [DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1) for ff in
                                 function_features]
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/graphcodebert-base')
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)
    token_count = []
    for data_item in tqdm(positive_train_data_items):
        text = data_item.get_train_text(tokenizer.sep_token)
        tokens = tokenizer.tokenize(text)

        # 检查tokens的数量
        # if len(tokens) > 512:
        #     print(data_item.function_name, len(tokens))
        token_count.append({
            "function_name": data_item.function_name,
            "token_count": len(tokens),
            "src_code_count": len(data_item.src_codes),
            "src_string_count": len(data_item.src_strings),
            "src_number_count": len(data_item.src_numbers),
            "asm_code_count": len(data_item.asm_codes),
            "bin_string_count": len(data_item.bin_strings),
            "bin_number_count": len(data_item.bin_numbers),
            "text": text
            # "asm_codes": data_item.asm_codes if len(tokens) <= 512 else None,
        })
    token_count.sort(key=lambda x: x["token_count"], reverse=True)
    save_to_json_file(token_count, "TestCases/model_train/model_1/train_data/token_count.json")


if __name__ == '__main__':
    # debug_convert_function_feature_to_train_data()
    # train_model_1()
    # debug_model_application()

    debug_token_length()
