import re
from multiprocessing import Pool
from typing import List

from loguru import logger
from tqdm import tqdm

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.src_tool import analyze_src_codes
from main.interface import DataItemForFunctionConfirmModel
from main.tc_models import VulFunction


def _is_reserved_function_name(function_name):
    """
    Check if a function name is reserved in C/C++.

    Args:
    function_name (str): The name of the function to check.

    Returns:
    bool: True if the function name is reserved, False otherwise.
    """
    # Regex to match reserved function names:
    # 1. Names that begin with an underscore followed by an uppercase letter (e.g., _A, _Z).
    # 2. Names that begin with two underscores.
    # 3. Names that contain two consecutive underscores anywhere.
    reserved_patterns = [
        r'^_[A-Z]',  # Starts with _ followed by an uppercase letter
        r'^__',  # Starts with two underscores
        r'.*__.*'  # Contains two consecutive underscores
    ]

    # Check each pattern against the function name
    for pattern in reserved_patterns:
        if re.match(pattern, function_name):
            return True

    return False


def _generate_function_confirm_model_input(asm_function, vul_function: VulFunction):
    # 过滤条件 1：保留函数名
    if _is_reserved_function_name(asm_function.function_name):
        return None

    # 构成模型输入
    asm_codes, _ = asm_function.get_asm_codes()
    data_item = DataItemForFunctionConfirmModel(function_name=vul_function.get_function_name(),
                                                src_codes=vul_function.get_source_codes(),
                                                src_strings=[],
                                                src_numbers=[],
                                                asm_codes=asm_codes,
                                                bin_strings=[],
                                                bin_numbers=[],
                                                bin_function_name=asm_function.function_name,
                                                )
    # 正规化处理
    data_item.normalize()

    # 过滤条件 2：汇编代码长度检验
    if not 1 < len(data_item.asm_codes) / len(data_item.src_codes):
        return None

    # 过滤条件 3：参数数量检验
    asm_body_start_index, asm_param_count = analyze_asm_codes(data_item.asm_codes)
    src_body_start_index, src_param_count = analyze_src_codes(data_item.src_codes)

    if asm_param_count != src_param_count:
        if vul_function.get_function_name() == asm_function.function_name:
            logger.warning(
                f"\t\tmissing vul function:: {vul_function.get_function_name()}, {src_param_count}, {asm_param_count}")
            logger.warning(f"\t\tsrc codes: {data_item.src_codes}")
            logger.warning(f"\t\tasm codes: {data_item.asm_codes}")
        return None

    # 截去函数定义和参数部分
    data_item.asm_codes = data_item.asm_codes[asm_body_start_index:]
    data_item.src_codes = data_item.src_codes[src_body_start_index:]

    return data_item


def _generate_function_confirm_model_input_wrapper(args):
    asm_function, vul_function = args
    return _generate_function_confirm_model_input(asm_function, vul_function)


def filter_and_generate_function_confirm_model_input(vul_functions: List[VulFunction], asm_function_dict):
    data_items = []
    tasks = [(asm_function, vul_function)
             for vul_function in vul_functions
             for asm_function in asm_function_dict.values()]
    with Pool() as pool:
        results = pool.imap_unordered(_generate_function_confirm_model_input_wrapper, tasks)
        for data_item in tqdm(results, f"filter_and_generate_function_confirm_model_input", total=len(tasks)):
            if data_item is None:
                continue
            data_items.append(data_item)
    logger.success(f"filter: {len(tasks)} ---> {len(data_items)}")
    return data_items
