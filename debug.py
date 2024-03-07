from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import FunctionFeatureExtractor
from main.extractors.src_function_feature_extractor.entities import ProjectFeature


def debug_extract_src_function_feature():
    openssl_src_path = r"C:\Users\liuchengyue\Desktop\projects\GithubProjects\openssl"
    openssl_src_feature = r"TestCases/feature_extraction/openssl_src_feature.json"

    extractor = FunctionFeatureExtractor()
    project_src_feature: ProjectFeature = extractor.extract_project_src_feature(openssl_src_path)

    save_to_json_file(project_src_feature.custom_serialize(), openssl_src_feature)


if __name__ == '__main__':
    debug_extract_src_function_feature()
