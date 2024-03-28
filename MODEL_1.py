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
O0_libcrypto_bin_path = r"TestCases/binaries/self_compiled/opensl_3.2.1/O0/libcrypto.so.3"
O0_openssl_bin_path = r"TestCases/binaries/self_compiled/opensl_3.2.1/O0/openssl"
O0_libssl_bin_path = r"TestCases/binaries/self_compiled/opensl_3.2.1/O0/libssl.so.3"

# openssl matched_function_feature
openssl_function_features_path = r"TestCases/feature_extraction/openssl_feature/function_features.json"

# train_data_items
train_data_save_path = r"TestCases/model_train/model_1/train_data/train_data.json"
val_data_save_path = r"TestCases/model_train/model_1/train_data/val_data.json"
test_data_save_path = r"TestCases/model_train/model_1/train_data/test_data.json"

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
        # (linux_kernel_dir, linux_kernel_path),
    ]

    # self_compiled bin
    src_bin_pairs = [
        (libcrypto_src_dir, O0_libcrypto_bin_path),  # openssl O0 3.2.1
        (openssl_src_dir, O0_openssl_bin_path),  # openssl O0 3.2.1
        (libssl_src_dir, O0_libssl_bin_path),  # openssl O0 3.2.1
    ]

    # 提取函数特征, 注意，这里有筛选，只提取长度在7-100之间的函数
    extract_matched_function_feature(
        src_bin_pairs=src_bin_pairs,
        save_path=openssl_function_features_path,
    )

    # 转换成训练数据 1:5, 0.2的相似度，效果很好 97%准确率
    """
    多进行几次实验，争取找到最好的训练样本比例和相似度阈值,以下实验结果，除特殊注明外，都是在debian二进制上实验的
    正负1:1   0.2的相似度阈值，
    正负1:1   0.5的相似度阈值，
    正负1:3   0.2的相似度阈值，94%
    正负1:3   0.5的相似度阈值，94%，但是过拟合的比0.2差一点，应该是能够学习到更多的细节
    正负1:5   0.2的相似度阈值，97%
    正负1:5   0.5的相似度阈值，
    正负1:10  0.2的相似度阈值，
    正负1:10  0.5的相似度阈值，97.8%
    正负1:10  0.5的相似度阈值，（自己编译的O0级别），正在测试中
    """
    convert_function_feature_to_train_data(openssl_function_features_path,
                                           train_data_save_path,
                                           val_data_save_path,
                                           test_data_save_path,
                                           negative_ratio=10,
                                           similarity_threshold=0.5)


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
    # Done
    # prepare_train_data_for_model_1()

    # Done
    train_model_1()
