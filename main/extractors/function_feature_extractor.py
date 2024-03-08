import os
import subprocess
from typing import List

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file, check_file_path, save_to_json_file
from main.extractors.src_function_feature_extractor.entities import ProjectFeature, NodeType
from main.extractors.src_function_feature_extractor.tree_sitter_extractor import ProjectFeatureExtractor
from main.interface import SrcFunctionFeature, BinFunctionFeature, FunctionFeature
from setting.paths import IDA_PRO_PATH, IDA_PRO_SCRIPT_PATH, IDA_PRO_OUTPUT_PATH


def extract_function_feature(project_path: str, binary_file_paths: List[str], save_path: str):
    # 提取源码特征
    src_function_features = extract_src_feature(project_path)

    # 提取二进制特征
    bin_function_features = []
    for binary_file_path in tqdm(binary_file_paths, desc="Extracting binary features"):
        bin_function_features.extend(extract_bin_feature(binary_file_path))

    # 找到相同的函数，从而能够合并特征
    matched_function_names = set()
    unmatched_function_names = set()
    function_feature_dict = {}
    for bin_function_feature in bin_function_features:
        for src_function_feature in src_function_features:
            if src_function_feature.name == bin_function_feature.name:
                matched_function_names.add(src_function_feature.name)
                if (function_feature := function_feature_dict.get(f"{src_function_feature.name}")) is None:
                    function_feature_dict[f"{src_function_feature.name}"] = function_feature = FunctionFeature(
                        function_name=src_function_feature.name,
                        bin_function_feature=bin_function_feature,
                        src_function_features=[src_function_feature]
                    )
                # 重复性检查
                redundant = False
                for ssf in function_feature.src_function_features:
                    if src_function_feature.hash_value == ssf.hash_value:
                        redundant = True
                        break
                if not redundant:
                    function_feature.src_function_features.append(src_function_feature)
            else:
                unmatched_function_names.add(src_function_feature.name)
    count = 0
    for function_feature in function_feature_dict.values():
        if len(function_feature.src_function_features) == 1:
            count += len(function_feature.src_function_features)
    print(f"matched_function_names num: {len(matched_function_names)}\n"
          f"unmatched_function_names num: {len(unmatched_function_names)}\n"
          f"count: {count}")

    # 保存结果
    save_data = [f.custom_serialize() for f in function_feature_dict.values()]
    save_to_json_file(save_data, save_path)


def extract_src_feature(project_path) -> List[SrcFunctionFeature]:
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
                file_path=file_feature.file_path,
                line_start=node_feature.start_line,
                line_end=node_feature.end_line,
                original_lines=[line.rstrip() for line in node_feature.source_codes],
                strings=function_strings,
                numbers=[],
                hash_value=node_feature.normalized_hash
            )
            src_function_features.append(src_function_feature)

    return src_function_features


def extract_bin_feature(binary_file) -> List[BinFunctionFeature]:
    """
    使用ida提取项目的特征，转换成外部的数据结构
    :return:
    """

    if not os.path.exists(binary_file):
        raise FileNotFoundError(f"Binary file not found: {binary_file}")

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

    function_name_list = [f.name for f in bin_function_features]
    function_nam_set = set(function_name_list)
    print(f"function_name_list num: {len(function_name_list)}\n"
          f"function_nam_set num: {len(function_nam_set)}")
    return bin_function_features
