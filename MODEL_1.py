import copy
import os
import random
import traceback
from random import shuffle

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import save_to_json_file, load_from_json_file
from bintools.general.normalize import normalize_asm_lines
from main.extractors.function_feature_extractor import extract_matched_function_feature
from main.interface import TrainFunction
from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data, \
    levenshtein_distance, generate_data_items_from_train_functions, shuffle_and_split
from main.models.function_confirm_model.model_application import FunctionFinder
from setting.settings import ASM_CODE_NUM

# raw input
# src
libcrypto_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\crypto"
openssl_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\apps"
libssl_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\openssl\ssl"
libpng_src_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\libpng"

# arch/：特定于架构的代码，如x86、ARM等。
# kernel/：内核的核心功能，如进程管理和调度。
# mm/：内存管理相关的代码。
# fs/：文件系统的实现。
# net/：网络协议和功能的实现。
# drivers/：设备驱动程序。
# lib/：一些基本库函数。
linux_kernel_dir = r"C:\Users\chengyue\Desktop\projects\github_projects\linux-6.8.2_for_extraction"

# debian bin
libcrypto_bin_path = r"TestCases/binaries/debian/openssl_3.2.1/libcrypto.so.3"
openssl_bin_path = r"TestCases/binaries/debian/openssl_3.2.1/openssl"
libssl_bin_path = r"TestCases/binaries/debian/openssl_3.2.1/libssl.so.3"
libpng_bin_path = r"TestCases/binaries/debian/libpng/libpng16.so.16.43.0"
linux_kernel_path = "TestCases/binaries/linux_kernel_6.8.2/vmlinux"

# self compiled bin
O0_libcrypto_bin_path = r"TestCases/binaries/self_compiled/openssl_3.2.1/O0/libcrypto.so.3"
O0_openssl_bin_path = r"TestCases/binaries/self_compiled/openssl_3.2.1/O0/openssl"
O0_libssl_bin_path = r"TestCases/binaries/self_compiled/openssl_3.2.1/O0/libssl.so.3"

# openssl matched_function_feature
openssl_function_features_path = r"TestCases/feature_extraction/openssl_feature/function_features.json"

# train_data_items
train_data_save_path = r"TestCases/model_train/model_1/train_data_50000/train_data.json"
val_data_save_path = r"TestCases/model_train/model_1/train_data_50000/val_data.json"
test_data_save_path = r"TestCases/model_train/model_1/train_data_50000/test_data.json"

linux_kernel_train_data_save_path = r"TestCases/model_train/model_1/linux_kernel_train_data/train_data.json"
linux_kernel_val_data_save_path = r"TestCases/model_train/model_1/linux_kernel_train_data/val_data.json"
linux_kernel_test_data_save_path = r"TestCases/model_train/model_1/linux_kernel_train_data/test_data.json"


def prepare_train_data_for_model_1():
    """
    1. 从源代码和二进制文件中提取函数特征: 需要准备源代码和对应的二进制文件，需要保持版本一致。
    2. 把函数特征转换成训练数据
    :return:
    """
    # debian bin
    src_bin_pairs = [
        (libcrypto_src_dir, libcrypto_bin_path),  # openssl O2 3.2.1
        (openssl_src_dir, openssl_bin_path),  # openssl O2 3.2.1
        (libssl_src_dir, libssl_bin_path),  # openssl O2 3.2.1
        (libpng_src_dir, libpng_bin_path),  # libpng O2 16.43
    ]

    # self_compiled bin
    # src_bin_pairs = [
    #     (libcrypto_src_dir, O0_libcrypto_bin_path),  # openssl O0 3.2.1
    #     (openssl_src_dir, O0_openssl_bin_path),  # openssl O0 3.2.1
    #     (libssl_src_dir, O0_libssl_bin_path),  # openssl O0 3.2.1
    # ]

    # 提取函数特征, 注意，这里有筛选，只提取长度在7-100之间的函数
    extract_matched_function_feature(
        src_bin_pairs=src_bin_pairs,
        save_path=openssl_function_features_path,
    )

    # 转换成训练数据 1:5, 0.2的相似度，效果很好 97%准确率
    """
    多进行几次实验，争取找到最好的训练样本比例和相似度阈值,以下实验结果，除特殊注明外，都是在debian二进制上实验的
    1:3     0.5     97
    """
    convert_function_feature_to_train_data(openssl_function_features_path,
                                           train_data_save_path,
                                           val_data_save_path,
                                           test_data_save_path,
                                           negative_ratio=5,
                                           similarity_threshold=0.5)


def prepare_train_data_for_model_1_new():
    # 加载TrainFunction json数据
    logger.info(f"loading train functions from json file...")
    train_functions_json_items = load_from_json_file("test_results/compiled_paths.json")
    shuffle(train_functions_json_items)

    # 转换成TrainFunction对象
    logger.info(f"converting json items to TrainFunction objects...")
    train_functions = [TrainFunction.init_from_dict(item) for item in train_functions_json_items[:1000]]

    # 筛选数据
    # shuffle and split
    logger.info(f"shuffling and splitting...")
    train_functions, valid_functions, test_functions = shuffle_and_split(train_functions)

    # train data
    logger.info(f"generating train data...")
    all_data_items = generate_data_items_from_train_functions(train_functions)
    save_to_json_file([data_item.custom_serialize() for data_item in all_data_items], train_data_save_path, output_log=True)
    logger.info(f"done, data_items_num: {len(all_data_items)}")

    # valid data
    logger.info(f'generating valid data...')
    all_data_items = generate_data_items_from_train_functions(valid_functions)
    save_to_json_file([data_item.custom_serialize() for data_item in all_data_items], val_data_save_path, output_log=True)
    logger.info(f"done, data_items_num: {len(all_data_items)}")

    # test data
    logger.info(f"generating test data...")
    all_data_items = generate_data_items_from_train_functions(test_functions)
    save_to_json_file([data_item.custom_serialize() for data_item in all_data_items], test_data_save_path, output_log=True)
    logger.info(f"done, data_items_num: {len(all_data_items)}")

    logger.info(f"all_done!")


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
        epochs=30,
        batch_size=100,
    )


if __name__ == '__main__':
    # prepare_train_data_for_model_1()
    prepare_train_data_for_model_1_new()
    train_model_1()

    """
    两个版本，1:20， 最终99.09%
    """
