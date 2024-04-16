import re
from typing import List

from loguru import logger

from main.interface import AsmFunction, CodeMapping


def parse_objdump_file(dump_file_path, ignore_warnings=False):
    if not ignore_warnings:
        logger.warning(f"THIS FUNCTION WILL FILTER ASM FUNCTIONS which has less than 10 lines of code.")
    try:
        with open(dump_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Failed to read file {dump_file_path}, error: {e}")
        return {}

    # 1. 找到.text节
    text_section_lines = find_text_section_lines(lines)

    # 2. 拆分函数行
    function_lines_dict = split_asm_functions(text_section_lines)

    # 3. 解析函数行
    asm_functions = []
    for function_name, function_lines in function_lines_dict.items():
        asm_functions.append(AsmFunction(function_name=function_name,
                                         code_mappings=parse_function_lines(function_lines)))

    # 4. 基本筛选并生成函数字典
    #    1. 至少10行汇编代码
    #    2. 更多其他后续补充
    asm_function_dict = {}
    for asm_function in asm_functions:
        if asm_function.count_asm_codes() < 10:
            continue
        asm_function_dict[asm_function.function_name] = asm_function
    return asm_function_dict


def find_text_section_lines(lines):
    start_flag = False
    text_section_lines = []
    for line in lines:
        if line == "Disassembly of section .text:\n":
            start_flag = True
        elif line.startswith("Disassembly of section "):
            start_flag = False

        if not start_flag:
            continue

        text_section_lines.append(line)

    return text_section_lines


def split_asm_functions(text_section_lines):
    function_lines_dict = {}
    cur_function_name = None
    for line in text_section_lines:
        if " <" in line and line.endswith(">:\n"):
            cur_function_name = line.split()[1][1:-2]
            if '.' in cur_function_name:
                cur_function_name = cur_function_name.split('.')[0]
            cur_function_name = cur_function_name.strip()
            function_lines_dict[cur_function_name] = []
            continue

        if cur_function_name is None:
            continue

        function_lines_dict[cur_function_name].append(line)

    return function_lines_dict


def parse_function_lines(function_lines):
    code_mappings: List[CodeMapping] = []
    cur_function_name = None
    cur_code_mapping = CodeMapping()
    for line in function_lines:
        if line.endswith("():\n"):
            if cur_code_mapping and (cur_code_mapping.src_codes or cur_code_mapping.asm_codes):
                code_mappings.append(cur_code_mapping)
            cur_function_name = line[:-4]
            cur_function_name = cur_function_name.strip()
            cur_code_mapping = CodeMapping()
            cur_code_mapping.src_function_name = cur_function_name
            continue

        if is_location_line(line):
            if cur_code_mapping and (cur_code_mapping.src_codes or cur_code_mapping.asm_codes):
                code_mappings.append(cur_code_mapping)
            cur_function_file_path, cur_function_line_num, is_discriminator = parse_location_line(line)

            cur_code_mapping = CodeMapping()
            cur_code_mapping.src_function_name = cur_function_name
            cur_code_mapping.src_function_path = cur_function_file_path
            cur_code_mapping.src_code_line_num = cur_function_line_num
            cur_code_mapping.is_discriminator = is_discriminator
            continue

        # 如果是汇编代码行
        if is_assembly_line(line):
            parts = line.split("\t")
            if len(parts) != 3:
                continue
            asm_code = parts[-1].rstrip()
            cur_code_mapping.asm_codes.append(asm_code)
        # 如果不是汇编代码行，且当前没有汇编代码，那么就是源代码行
        elif not cur_code_mapping.asm_codes:
            src_code = line.rstrip()
            cur_code_mapping.src_codes.append(src_code)
        elif line.strip() == "" or line.strip() == "...":
            pass
        else:
            logger.warning(f"unexpected line: {line}")

    if cur_code_mapping and (cur_code_mapping.src_codes or cur_code_mapping.asm_codes):
        code_mappings.append(cur_code_mapping)

    return code_mappings


def is_location_line(line):
    """
    TODO 如果编译环境有变化这里要变化

    :param line:
    :return:
    """

    if ("__tmp/" in line or line.startswith("/usr/")) and ":" in line:
        return True
    return False


def parse_location_line(line):
    function_file_path, line_num = line.split(":")
    is_discriminator = False
    if "(discriminator" in line_num:
        line_num = line_num.split()[0]
        is_discriminator = True
    line_num = int(line_num)
    return function_file_path, line_num, is_discriminator


def is_assembly_line(line):
    pattern = r"^\s*[0-9a-f]+:\t([0-9a-f]{2} )+\s*(\S+)?"
    return re.match(pattern, line) is not None
