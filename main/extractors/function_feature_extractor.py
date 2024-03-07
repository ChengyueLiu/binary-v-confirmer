import subprocess
from typing import List

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file, check_file_path
from main.extractors.src_function_feature_extractor.entities import ProjectFeature, NodeType
from main.extractors.src_function_feature_extractor.tree_sitter_extractor import ProjectFeatureExtractor
from main.interface import SrcFunctionFeature, BinFunctionFeature
from setting.paths import IDA_PRO_PATH, IDA_PRO_SCRIPT_PATH, IDA_PRO_OUTPUT_PATH


class FunctionFeatureExtractor:

    def __init__(self):
        pass

    def extract(self, project_path: str, binary_file_paths: List[str]):
        # 提取源码特征
        src_function_features = self.extract_src_feature(project_path)

        # 提取二进制特征
        bin_function_features = []
        for binary_file_path in tqdm(binary_file_paths, desc="Extracting binary features"):
            bin_function_features.extend(self.extract_bin_feature(binary_file_path))

        # 找到相同的函数，从而能够合并特征
        matched_function_names = set()
        unmatched_function_names = set()
        for bin_function_feature in bin_function_features:
            for src_function_feature in src_function_features:
                if src_function_feature.name == bin_function_feature.name:
                    matched_function_names.add(src_function_feature.name)
                else:
                    unmatched_function_names.add(src_function_feature.name)
        print(f"matched_function_names num: {len(matched_function_names)}\n"
              f"unmatched_function_names num: {len(unmatched_function_names)}")

    def extract_src_feature(self, project_path) -> List[SrcFunctionFeature]:
        """
        使用tree-sitter提取项目的特征，转换成外部的数据结构

        :param project_path:
        :return:
        """
        # 提取特征
        extractor = ProjectFeatureExtractor(project_path)
        extractor.extract()

        # 转换成外部的数据结构
        src_function_features: List[SrcFunctionFeature] = []
        for file_feature in extractor.result.file_features:
            for node_feature in file_feature.node_features:
                if node_feature.type not in [NodeType.function_declarator.value, NodeType.function_definition.value]:
                    continue
                function_strings = []
                function_strings.extend(node_feature.must_compile_string_group)
                for string_group in node_feature.conditional_compile_string_groups:
                    function_strings.extend(string_group)

                src_function_feature = SrcFunctionFeature(
                    name=node_feature.name,
                    original_lines=node_feature.source_codes,
                    strings=function_strings,
                    numbers=[],
                    hash_value=node_feature.normalized_hash
                )
                src_function_features.append(src_function_feature)

        return src_function_features

    def extract_bin_feature(self, binary_file) -> List[BinFunctionFeature]:
        """
        使用ida提取项目的特征，转换成外部的数据结构
        :return:
        """
        # 构造IDA Pro命令行命令
        command = [
            f"{IDA_PRO_PATH}",
            "-A",  # 分析完成后自动退出
            f"-S\"{IDA_PRO_SCRIPT_PATH}\"",  # 指定执行的脚本
            f"\"{binary_file}\""  # 指定分析的二进制文件
        ]

        # 使用subprocess调用IDA Pro
        try:
            subprocess.run(" ".join(command), check=True, shell=True)
            logger.debug("IDA Pro analysis completed successfully.")


        except subprocess.CalledProcessError as e:
            raise Exception(f"Error during IDA Pro analysis: {e}")

        # 读取IDA Pro输出的结果
        check_file_path(IDA_PRO_OUTPUT_PATH)
        results = load_from_json_file(IDA_PRO_OUTPUT_PATH)

        # 转换成外部的数据结构
        bin_function_features: List[BinFunctionFeature] = [BinFunctionFeature.init_from_dict(data=json_item)
                                                           for json_item in results]
        return bin_function_features

    def merge_src_and_bin_features(self, src_function_features_path, bin_function_features_path):
        # 在文件中加载
        bin_function_features: List[BinFunctionFeature] = BinFunctionFeature.init_from_json_file(
            bin_function_features_path)
        src_function_features: List[SrcFunctionFeature] = SrcFunctionFeature.init_from_json_file(
            src_function_features_path)

        # 为每个源码函数特征找到对应的二进制函数特征
        matched_function_names = set()
        unmatched_function_names = set()
        for bin_function_feature in bin_function_features:
            for src_function_feature in src_function_features:
                if src_function_feature.name == bin_function_feature.name:
                    matched_function_names.add(src_function_feature.name)
                else:
                    unmatched_function_names.add(src_function_feature.name)
        print(f"matched_function_names num: {len(matched_function_names)},\n"
              f"unmatched_function_names num: {len(unmatched_function_names)}")
