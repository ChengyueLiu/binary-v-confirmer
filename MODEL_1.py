import os

from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import extract_matched_function_feature
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data
from main.models.function_confirm_model.model_application import FunctionFinder

# raw input
# src
openssl_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\openssl"

# bin
libcrypto_bin_path = r"TestCases/feature_extraction/binaries/libcrypto.so.3"
openssl_bin_path = r"TestCases/feature_extraction/binaries/openssl"
libssl_bin_path = r"TestCases/feature_extraction/binaries/libssl.so.3"

# openssl matched_function_feature
openssl_function_features_path = r"TestCases/feature_extraction/openssl_feature/function_features.json"

# openssl train data items
openssl_train_data_save_path = r"TestCases/model_train/model_1/train_data/openssl/train_data.json"
openssl_val_data_save_path = r"TestCases/model_train/model_1/train_data/openssl/val_data.json"
openssl_test_data_save_path = r"TestCases/model_train/model_1/train_data/openssl/test_data.json"

# libpng train data items
# src
libpng_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\libpng"

# bin
libpng_bin_path = r"TestCases/feature_extraction/binaries/libpng16.so.16.44.0"
png_fix_itxt_bin_path = r"TestCases/feature_extraction/binaries/png-fix-itxt"
pngfix_bin_path = r"TestCases/feature_extraction/binaries/pngfix"

libpng_function_features_path = r"TestCases/feature_extraction/libpng_feature/function_features.json"

libpng_train_data_save_path = r"TestCases/model_train/model_1/train_data/libpng/train_data.json"
libpng_val_data_save_path = r"TestCases/model_train/model_1/train_data/libpng/val_data.json"
libpng_test_data_save_path = r"TestCases/model_train/model_1/train_data/libpng/test_data.json"


def prepare_train_data_for_model_1():
    """
    1. 从源代码和二进制文件中提取函数特征: 需要准备源代码和对应的二进制文件，需要保持版本一致。
    2. 把函数特征转换成训练数据
    :return:
    """
    # 提取原始特征
    extract_matched_function_feature(
        project_path=openssl_src_path,
        binary_file_paths=[libcrypto_bin_path, openssl_bin_path, libssl_bin_path],
        save_path=openssl_function_features_path,
    )
    # 转换成训练数据
    convert_function_feature_to_train_data(openssl_function_features_path,
                                           openssl_train_data_save_path,
                                           openssl_val_data_save_path,
                                           openssl_test_data_save_path,
                                           negative_ratio=5)

    # 提取原始特征
    extract_matched_function_feature(
        project_path=libpng_src_path,
        binary_file_paths=[libpng_bin_path, png_fix_itxt_bin_path, pngfix_bin_path],
        save_path=libpng_function_features_path
    )
    convert_function_feature_to_train_data(libpng_function_features_path,
                                           libpng_train_data_save_path,
                                           libpng_val_data_save_path,
                                           libpng_test_data_save_path,
                                           negative_ratio=5)


def train_model_1():
    """
    训练模型
    主要在linux上运行，windows上会比较慢

    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    run_train(
        openssl_train_data_save_path,
        openssl_val_data_save_path,
        libpng_train_data_save_path,
        epochs=3,
        batch_size=100,
        test_only=True)


def test_model_1_by_openssl():
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
    # model_save_path = os.path.join(root_dir, "model_weights.pth")
    model_save_path = r"Resources/model_weights/model_1_weights.pth"
    vul_function_finder = FunctionFinder(
        model_save_path=model_save_path,
        batch_size=batch_size
    )
    similar_functions_dict = {}
    # 三个漏洞，三个二进制文件
    for binary in [openssl, libcrypto, libssl]:
        similar_functions_dict[binary] = binary_similar_functions_dict = {}
        for vul_function_name in ["*PKCS12_unpack_p7data", "*PKCS12_unpack_p7encdata", "*PKCS12_unpack_authsafes"]:
            logger.info(f"Finding similar functions for {vul_function_name} in {binary}")
            bin_function_num, similar_functions = vul_function_finder.find_similar_bin_functions(
                src_file_path=vul_function_file_path,
                cause_function_name=vul_function_name,
                binary_file_abs_path=binary)

            binary_similar_functions_dict[vul_function_name] = {
                "vul_function_name": vul_function_name,
                "all_function_num": bin_function_num,
                "similar_function_num": len(similar_functions),
                "similar_funct ions": similar_functions
            }
    result_path = os.path.join(test_data_dir, "similar_functions.json")
    save_to_json_file(similar_functions_dict, result_path)
    logger.info(f"Result saved to {result_path}")
    logger.info(f"Done")


if __name__ == '__main__':
    # Done
    prepare_train_data_for_model_1()

    # Done
    # train_model_1()

    # Done
    # test_model_1_by_openssl()

    # TODO test_model_1_by_more_test_cases()
