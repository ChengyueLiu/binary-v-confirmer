from typing import List

from loguru import logger

from bintools.general.file_tool import check_file_path
from main.extractors.function_feature_extractor import extract_bin_feature, extract_src_feature_for_specific_function


def find_similar_functions(src_file_path: str, vul_function_name: str, binary_file_abs_path: str):
    """
    输入一个源代码函数代码，和一个二进制文件，返回二进制文件中与源代码函数相似的汇编函数

    """
    src_file_path = check_file_path(src_file_path)
    binary_file_abs_path = check_file_path(binary_file_abs_path)

    # step 1 提取源代码特征
    logger.info(f"Extracting feature for {src_file_path}")
    src_function_feature = extract_src_feature_for_specific_function(file_path=src_file_path,
                                                                     vul_function_name=vul_function_name)
    if src_function_feature is None:
        logger.error(f"Can't find function {vul_function_name} in {src_file_path}")
        return None

    logger.info(f"Feature extracted for {src_file_path}")
    # step 2 提取二进制文件特征
    logger.info(f"Extracting feature for {binary_file_abs_path}")
    bin_function_features = extract_bin_feature(binary_file_abs_path)
    logger.info(f"{len(bin_function_features)} features extracted for {binary_file_abs_path}")

    # step 3 使用模型遍历比较源代码函数和二进制文件函数

    # step 4 返回标签为1的函数

    pass
