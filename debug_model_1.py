import os
import subprocess

from loguru import logger

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

    root_dir = r"/home/chengyue/projects/binary-v-confirmer/"
    # root_dir = r"C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer"
    import os
    os.environ["CUDA_VISIBLE_DEVICES"] = "0"

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

    batch_size = 16

    vul_function_finder = VulFunctionFinder(
        model_save_path=model_save_path,
        batch_size=batch_size
    )
    similar_functions_dict = {}
    for binary in [openssl, libcrypto, libssl]:
        logger.info(f"Finding similar functions for {vul_function_name} in {binary}")
        similar_functions = vul_function_finder.find_similar_functions(src_file_path=vul_function_file_path,
                                                   vul_function_name=vul_function_name,
                                                   binary_file_abs_path=binary)
        similar_functions.sort(key=lambda x: x[1], reverse=True)
        similar_functions_dict[binary] = similar_functions
    logger.info(f"Done")


def train_model_1():
    """
    训练模型1, 这个不是一个调试函数，而是一个可用的训练函数

    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    data_file_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    run_train(data_file_path, epochs=3, batch_size=16)


if __name__ == '__main__':
    # debug_convert_function_feature_to_train_data()
    # train_model_1()
    debug_model_application()
