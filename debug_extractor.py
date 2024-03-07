from typing import List

from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import FunctionFeatureExtractor
from main.interface import SrcFunctionFeature

openssl_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\openssl"
openssl_src_feature = r"TestCases/feature_extraction/openssl_src_feature.json"

libcrypto_bin_path = r"TestCases/feature_extraction/binaries/libcrypto.so.3"
libcrypto_bin_feature = r"TestCases/feature_extraction/libcrypto_bin_feature.json"

openssl_bin_path = r"TestCases/feature_extraction/binaries/openssl"
libssl_bin_path = r"TestCases/feature_extraction/binaries/libssl.so.3"


def debug_extract_src_function_feature():
    """
    提取源码函数特征
    :return:
    """

    extractor = FunctionFeatureExtractor()
    src_function_features: List[SrcFunctionFeature] = extractor.extract_src_feature(openssl_src_path)

    save_data = [f.custom_serialize() for f in src_function_features]
    save_to_json_file(save_data, openssl_src_feature)


def debug_extract_asm_function_feature():
    """
    提取二进制函数特征
    :return:
    """

    extractor = FunctionFeatureExtractor()
    asm_function_features = extractor.extract_bin_feature(libcrypto_bin_path)

    save_data = [f.custom_serialize() for f in asm_function_features]
    save_to_json_file(save_data, libcrypto_bin_feature)


def debug_merge_features():
    """
    尝试找到相同的函数，从而能够合并特征
    :return:
    """
    extractor = FunctionFeatureExtractor()
    extractor.merge_src_and_bin_features(openssl_src_feature, libcrypto_bin_feature)


def debug_extract():
    """
    调试提取特征的整个流程
    :return:
    """

    extractor = FunctionFeatureExtractor()
    extractor.extract(openssl_src_path, [libcrypto_bin_path, openssl_bin_path, libssl_bin_path])


if __name__ == '__main__':
    # debug_extract_src_function_feature()
    # debug_extract_asm_function_feature()
    # debug_merge_features()
    debug_extract()
