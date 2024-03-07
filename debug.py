from typing import List

from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import FunctionFeatureExtractor
from main.extractors.src_function_feature_extractor.entities import ProjectFeature
from main.interface import SrcFunctionFeature


def debug_extract_src_function_feature():
    openssl_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\openssl"
    openssl_src_feature = r"TestCases/feature_extraction/openssl_src_feature.json"

    extractor = FunctionFeatureExtractor()
    src_function_features: List[SrcFunctionFeature] = extractor.extract_src_feature(openssl_src_path)

    save_data = [f.custom_serialize() for f in src_function_features]
    save_to_json_file(save_data, openssl_src_feature)


def debug_extract_asm_function_feature():
    openssl_bin_path = r"TestCases/feature_extraction/libcrypto.so.3"
    openssl_bin_feature = r"TestCases/feature_extraction/openssl_bin_feature.json"

    extractor = FunctionFeatureExtractor()
    asm_function_features = extractor.extract_bin_feature(openssl_bin_path)

    save_data = [f.custom_serialize() for f in asm_function_features]
    save_to_json_file(save_data, openssl_bin_feature)


if __name__ == '__main__':
    # debug_extract_src_function_feature()
    debug_extract_asm_function_feature()
