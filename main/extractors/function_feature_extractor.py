import subprocess
from typing import List

from loguru import logger

from bintools.general.file_tool import load_from_json_file, check_file_path
from main.extractors.src_function_feature_extractor.entities import ProjectFeature, NodeType
from main.extractors.src_function_feature_extractor.tree_sitter_extractor import ProjectFeatureExtractor
from main.interface import SrcFunctionFeature, AsmFunctionFeature
from setting.paths import IDA_PRO_PATH, IDA_PRO_SCRIPT_PATH, IDA_PRO_OUTPUT_PATH


class FunctionFeatureExtractor:

    def __init__(self):
        pass

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

    def extract_bin_feature(self, binary_file) -> List[AsmFunctionFeature]:
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

        check_file_path(IDA_PRO_OUTPUT_PATH)
        results = load_from_json_file(IDA_PRO_OUTPUT_PATH)

        asm_function_features: List[AsmFunctionFeature] = [AsmFunctionFeature.init_from_dict(data=json_item)
                                                           for json_item in results]
        return asm_function_features
