import os
import subprocess
from typing import List

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file, check_file_path, save_to_json_file
from main.extractors.src_function_feature_extractor.entities import ProjectFeature, NodeType
from main.extractors.src_function_feature_extractor.tree_sitter_extractor import ProjectFeatureExtractor, \
    FileFeatureExtractor
from main.interface import SrcFunctionFeature, BinFunctionFeature, FunctionFeature
from setting.paths import IDA_PRO_PATH, IDA_PRO_SCRIPT_PATH, IDA_PRO_OUTPUT_PATH


def extract_matched_function_feature(src_bin_pairs, save_path: str):
    """
    同时提取源码和二进制文件的特征，并把相同函数的特征，保存到指定路径，后续可以用于训练模型

    :param src_dir_path:
    :param binary_file_paths:
    :param save_path:
    :return:
    """
    results = []
    bin_function_names = {}
    src_function_names = {}
    for src_dir_path, binary_file_path in tqdm(src_bin_pairs):
        # 提取源码特征
        src_function_features = extract_src_feature_for_project(src_dir_path)
        src_function_names[src_dir_path] = sorted([f"{f.file_path}: {f.name}" for f in src_function_features])

        # 提取二进制特征
        bin_function_features = extract_bin_feature(binary_file_path)
        bin_function_names[binary_file_path] = sorted([f.name for f in bin_function_features])

        # 找到相同的函数，从而能够合并特征
        function_feature_dict = {}
        for src_function_feature in src_function_features:
            # 跳过太短的函数
            if len(src_function_feature.original_lines) < 7 or len(src_function_feature.original_lines) > 100:
                continue
            for bin_function_feature in bin_function_features:
                src_function_name = src_function_feature.name
                if src_function_name.startswith("*"):
                    src_function_name = src_function_name[1:]
                if src_function_name == bin_function_feature.name:
                    function_feature_dict[src_function_feature.name] = FunctionFeature(
                        function_name=src_function_feature.name,
                        bin_function_feature=bin_function_feature,
                        src_function_features=[src_function_feature]
                    )
        result = [f.custom_serialize() for f in function_feature_dict.values()]
        results.extend(result)
    save_to_json_file(bin_function_names,"TestCases/feature_extraction/openssl_feature/bin_function_names.json")
    save_to_json_file(src_function_names,"TestCases/feature_extraction/openssl_feature/src_function_names.json")
    # 保存结果
    save_to_json_file(results, save_path)


def extract_src_feature_for_project(project_path) -> List[SrcFunctionFeature]:
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
            if node_feature.type not in [NodeType.function_declarator.value, NodeType.function_definition.value,NodeType.pointer_declarator.value]:
                continue
            src_function_feature = SrcFunctionFeature.init_from_node_feature(file_path=file_feature.file_path,
                                                                             node_feature=node_feature)
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
    check_file_path(IDA_PRO_OUTPUT_PATH, '.json')
    results = load_from_json_file(IDA_PRO_OUTPUT_PATH)

    # 转换成外部的数据结构
    bin_function_features: List[BinFunctionFeature] = [BinFunctionFeature.init_from_dict(data=json_item)
                                                       for json_item in results]

    # function_name_list = [f.name for f in bin_function_features]
    # function_nam_set = set(function_name_list)
    # print(f"function_name_list num: {len(function_name_list)}\n"
    #       f"function_nam_set num: {len(function_nam_set)}")
    return bin_function_features


def extract_src_feature_for_specific_function(file_path: str, vul_function_name: str) -> SrcFunctionFeature | None:
    """
    提取源代码函数的特征, 并转换成FunctionFeature对象

    """
    extractor = FileFeatureExtractor(file_path)
    extractor.extract()
    file_feature = extractor.result
    # 这个是提取器的结果，是原始的对象，需要转换成现在程序中的对象。
    for node_feature in file_feature.node_features:
        if node_feature.name == vul_function_name:
            # 这个是转换成现在程序中的对象
            src_function_feature = SrcFunctionFeature.init_from_node_feature(file_path=file_feature.file_path,
                                                                             node_feature=node_feature)
            return src_function_feature

    return None
