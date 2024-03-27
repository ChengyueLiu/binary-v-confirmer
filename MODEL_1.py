import os

from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import extract_matched_function_feature
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data
from main.models.function_confirm_model.model_application import FunctionFinder

# raw input
# src
libcrypto_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\crypto"
openssl_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\apps"
libssl_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\ssl"
libpng_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\libpng"

# bin
libcrypto_bin_path = r"TestCases/binaries/openssl_3.2.1/libcrypto.so.3"
openssl_bin_path = r"TestCases/binaries/openssl_3.2.1/openssl"
libssl_bin_path = r"TestCases/binaries/openssl_3.2.1/libssl.so.3"
libpng_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\libpng"

# openssl matched_function_feature
openssl_function_features_path = r"TestCases/feature_extraction/openssl_feature/function_features.json"

# train_data_items
train_data_save_path = r"TestCases/model_train/model_1/train_data/train_data.json"
val_data_save_path = r"TestCases/model_train/model_1/train_data/val_data.json"
test_data_save_path = r"TestCases/model_train/model_1/train_data/test_data.json"


def prepare_train_data_for_model_1():
    """
    1. 从源代码和二进制文件中提取函数特征: 需要准备源代码和对应的二进制文件，需要保持版本一致。
    2. 把函数特征转换成训练数据
    :return:
    """

    src_bin_pairs = [
        (libcrypto_src_dir, libcrypto_bin_path),
        (openssl_src_dir, openssl_bin_path),
        (libssl_src_dir, libssl_bin_path),
        (libpng_src_dir, libssl_bin_path),
    ]
    # 提取原始特征, 源代码和汇编代码函数名相同，且源代码函数大于8行
    extract_matched_function_feature(
        src_bin_pairs=src_bin_pairs,
        save_path=openssl_function_features_path,
    )
    # 转换成训练数据
    convert_function_feature_to_train_data(openssl_function_features_path,
                                           train_data_save_path,
                                           val_data_save_path,
                                           test_data_save_path,
                                           negative_ratio=10)


def train_model_1():
    """
    训练模型
    主要在linux上运行，windows上会比较慢

    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    model_save_path = r"Resources/model_weights/model_1_weights.pth"
    run_train(
        train_data_save_path,
        val_data_save_path,
        test_data_json_file_path=test_data_save_path,
        model_save_path=model_save_path,
        test_only=False,
        epochs=10,
        batch_size=100,
    )


if __name__ == '__main__':
    # Done
    # prepare_train_data_for_model_1()

    # Done
    train_model_1()
