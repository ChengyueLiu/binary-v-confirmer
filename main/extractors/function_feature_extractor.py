from main.extractors.src_function_feature_extractor.entities import ProjectFeature
from main.extractors.src_function_feature_extractor.tree_sitter_extractor import ProjectFeatureExtractor


class FunctionFeatureExtractor:

    def __init__(self):
        pass

    def extract_project_src_feature(self, project_path) -> ProjectFeature:
        extractor = ProjectFeatureExtractor(project_path)
        extractor.extract()

        return extractor.result
