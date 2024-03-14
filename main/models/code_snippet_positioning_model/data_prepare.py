import copy
import json
import math
import os
import random
import traceback

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import find_files_in_dir, save_to_json_file, load_from_json_file
from main.interface import DataItemForCodeSnippetPositioningModel
from main.models.code_snippet_positioning_model.mapping_parser import MappingParser


def get_correspond_save_path(file_path: str, original_dir: str, save_dir: str,
                             original_ext=".mapping",
                             save_ext='.json'):
    """
    获取对应的保存路径
    :param file_path:
    :param original_dir:
    :param save_dir:
    :return:
    """
    file_path = os.path.normpath(file_path)
    original_dir = os.path.normpath(original_dir)
    save_dir = os.path.normpath(save_dir)

    dump_dir, dump_file = os.path.split(file_path)
    dump_dir = dump_dir.replace(original_dir, save_dir)
    os.makedirs(dump_dir, exist_ok=True)
    dump_file = dump_file.replace(original_ext, save_ext)
    dump_path = os.path.join(dump_dir, dump_file)
    return dump_path


def get_snippet_position(snippet, start_path) -> tuple[str, int, bool]:
    # 位置信息
    line_position = snippet["line_position"]
    abs_file_path, line_number = line_position.rsplit(":", 1)
    is_discriminator = False
    if " " in line_number:
        line_number = line_number.split(" ")[0]
        is_discriminator = True
    line_number = int(line_number)
    real_file_path = str(os.path.relpath(abs_file_path, start_path))
    return real_file_path, line_number, is_discriminator


def get_src_lines(sub_functions, start_path):
    src_code_dict = {}
    for sub_function in sub_functions:
        sub_function_name = sub_function["function_name"]
        if sub_function_name not in src_code_dict:
            src_code_dict[sub_function_name] = {
                "real_file_path": "",
                "src_codes": {}
            }

        snippets = sub_function["snippets"]
        for i, snippet in enumerate(snippets):
            # 位置信息
            real_file_path, line_number, is_discriminator = get_snippet_position(snippet, start_path)
            if not src_code_dict[sub_function_name]["real_file_path"]:
                src_code_dict[sub_function_name]["real_file_path"] = real_file_path

            source_codes = src_code_dict[sub_function_name]["src_codes"]
            # 代码片段
            src_lines = snippet["src_lines"]
            if src_lines:
                source_codes[line_number] = src_lines[-1]
                if i != 0:
                    for j, line in enumerate(src_lines[:-1], start=line_number - len(src_lines) + 1):
                        source_codes[j] = line

    return src_code_dict


def get_src_context(line_number, src_code_dict, previous_lines_range=2, next_lines_range=2):
    previous_lines = []
    for i in range(line_number - previous_lines_range, line_number):
        current_line = src_code_dict.get(i)
        if current_line:
            previous_lines.append(current_line)

    next_lines = []
    for i in range(line_number + 1, line_number + next_lines_range + 1):
        current_line = src_code_dict.get(i)
        if current_line:
            next_lines.append(current_line)

    return previous_lines, next_lines


def convert_mapping_to_json(original_mapping_file_dir, json_mapping_file_dir):
    """
    原始格式的mapping文件转换成json格式

    :param original_mapping_file_dir:
    :param json_mapping_file_dir:
    :return:
    """
    mapping_file_paths = find_files_in_dir(original_mapping_file_dir, ".mapping")
    parser = MappingParser()
    for file_path in tqdm(mapping_file_paths, desc="Parsing mapping files"):
        if os.path.getsize(file_path) < 100:
            os.remove(file_path)
            continue

        try:
            parser.parse(file_path)
        except Exception as e:
            logger.error(traceback.format_exc())
            logger.error(f"Failed to parse {file_path}: {e}")
            continue

        # Get the functions
        functions = copy.deepcopy(parser.functions)

        # Dump the functions to a json file
        dump_path = get_correspond_save_path(file_path, original_mapping_file_dir, json_mapping_file_dir)
        save_to_json_file(functions, dump_path)

        # Reset the parser
        parser.reset()


def convert_json_to_raw_train_data(original_mapping_file_dir, raw_train_data_json_dir):
    mapping_file_paths = find_files_in_dir(original_mapping_file_dir, ".json")
    for mapping_file_path in tqdm(mapping_file_paths, desc="Converting json to raw train data"):
        # TODO 目前只处理O0
        if "O0" not in mapping_file_path:
            continue
        # TODO 目前只处理openssl，所以开始地址写死了
        start_path = "/home/chengyue/test_cases/binary_sca_vul_confirmation/github_projects/openssl/"
        functions = load_from_json_file(mapping_file_path)

        all_raw_train_data_items = {}
        for function in functions:
            raw_train_data_items = []
            function_name = function["function_name"]
            if function_name == "mock_srv_ctx_free":
                print(1)
            sub_functions = function["sub_functions"]
            asm_codes = []
            # 第一轮遍历，找到所有的源代码
            src_code_dict = get_src_lines(sub_functions, start_path)
            # 第二轮编译，每行源代码和对应的汇编代码变成一条训练数据
            for sub_function in sub_functions:
                sub_function_name = sub_function["function_name"]
                current_src_code_dict = src_code_dict.get(sub_function_name, {})['src_codes']
                snippets = sub_function["snippets"]
                for snippet in snippets:
                    # 位置信息
                    real_file_path, line_number, is_discriminator = get_snippet_position(snippet, start_path)

                    # 代码片段
                    src_lines = snippet["src_lines"]
                    asm_lines = snippet["asm_lines"]

                    # 转换成训练数据
                    asm_codes.extend(asm_lines)
                    current_src_line = src_code_dict.get(sub_function_name, {})["src_codes"].get(line_number, None)
                    if current_src_line is None:
                        continue
                    previous_src_lines, next_src_lines = get_src_context(line_number, current_src_code_dict)

                    raw_train_data_items.append({
                        "function_name": function_name,
                        "sub_function_name": sub_function_name,
                        "real_file_path": real_file_path,
                        "line_number": line_number,
                        "is_discriminator": is_discriminator,
                        "previous_src_lines": previous_src_lines,
                        "current_src_line": current_src_line,
                        "next_src_lines": next_src_lines,
                        "asm_lines": asm_lines,
                    })
            all_raw_train_data_items[function_name] = raw_train_data_items
        save_path = get_correspond_save_path(mapping_file_path, original_mapping_file_dir, raw_train_data_json_dir,
                                             ".json",
                                             ".json")
        save_to_json_file(all_raw_train_data_items, save_path)


def convert_raw_train_data_to_train_data(raw_train_data_json_dir,
                                         train_data_json_file):
    # openssl, libcrypto, libssl
    test_path, train_path, valid_path = find_files_in_dir(raw_train_data_json_dir, ".json")
    raw_train_data = load_from_json_file(train_path)
    # raw_valid_data = load_from_json_file(valid_path)
    # raw_test_data = load_from_json_file(test_path)

    train_data = _convert_to_train_data(raw_train_data)
    # valid_data = _convert_to_train_data(raw_valid_data, min_src_lines, max_asm_lines)
    # test_data = _convert_to_train_data(raw_test_data, min_src_lines, max_asm_lines)

    save_to_json_file([train_data_item.custom_serialize() for train_data_item in train_data], train_data_json_file)


def _convert_to_train_data(raw_train_data, max_src_lines=5, max_asm_lines=50):
    # 合并 discriminator
    merge_discriminators(raw_train_data)

    # 随机截取片段: 不超过5行源代码，并且记住他们的上下文汇编代码
    train_data_items = random_select_snippets(max_src_lines, raw_train_data)

    data_items = []
    # 遍历这些片段，构成训练数据
    for function_name, left_raw_data_items, current_raw_data_items, right_raw_data_items in train_data_items:
        # 匹配的汇编源代码
        src_codes = [current_raw_data_item["current_src_line"] for current_raw_data_item in current_raw_data_items]

        # 匹配的汇编代码
        asm_codes = []
        for current_raw_data_item in current_raw_data_items:
            asm_codes.extend(current_raw_data_item["asm_lines"])

        # 补充答案上下文，计算答案位置
        answer_start_index, answer_end_index, answer_length, asm_codes = cal_answer_position(asm_codes,
                                                                                             left_raw_data_items,
                                                                                             max_asm_lines,
                                                                                             right_raw_data_items)

        # 筛选数据
        succeed = check_effective(src_codes, asm_codes)
        if not succeed:
            continue

        data_items.append(DataItemForCodeSnippetPositioningModel(
            function_name=function_name,
            src_codes=src_codes,
            asm_codes=asm_codes,
            answer_start_index=answer_start_index,
            answer_end_index=answer_end_index,
        ))
    return data_items


def merge_discriminators(raw_train_data):
    # 合并 discriminator
    for function_name, raw_data_items in raw_train_data.items():
        new_raw_data_items = []
        for raw_data_item in raw_data_items:
            if raw_data_item["is_discriminator"]:
                if new_raw_data_items and new_raw_data_items[-1]["line_number"] == raw_data_item["line_number"]:
                    new_raw_data_items[-1]["asm_lines"].extend(raw_data_item["asm_lines"])
                else:
                    new_raw_data_items.append(raw_data_item)
            else:
                new_raw_data_items.append(raw_data_item)
        raw_train_data[function_name] = new_raw_data_items


def random_select_snippets(max_src_lines, raw_train_data, max_num=3):
    train_data_items = []
    for function_name, raw_data_items in raw_train_data.items():
        if len(raw_data_items) < max_src_lines:
            train_data_items.append((function_name, [], raw_data_items, []))
            continue
        else:
            count = math.ceil(len(raw_data_items) / max_src_lines)
            if count > max_num:
                count = max_num
            while count > 0:
                start = random.randint(0, len(raw_data_items) - max_src_lines)
                end = start + max_src_lines
                current_raw_data_items = raw_data_items[start:end]
                left_raw_data_items = raw_data_items[:start]
                right_raw_data_items = raw_data_items[end:]

                train_data_items.append(
                    (function_name, left_raw_data_items, current_raw_data_items, right_raw_data_items))
                count -= 1
    return train_data_items


def cal_answer_position(asm_codes, left_raw_data_items, max_asm_lines, right_raw_data_items):
    # 答案位置
    answer_start_index = 0
    answer_end_index = len(asm_codes) - 1
    answer_length = len(asm_codes)
    # 添加上下文
    left_index = len(left_raw_data_items) - 1
    right_index = 0
    while len(asm_codes) < max_asm_lines:
        # 如果有左边的，先添加左边的
        if left_index >= 0:
            # 添加
            left_asm_codes = left_raw_data_items[left_index]["asm_lines"]
            asm_codes = left_asm_codes + asm_codes

            # 更新答案位置
            answer_start_index += len(left_asm_codes)
            answer_end_index += len(left_asm_codes)

            # 如果超过了50，就不添加了
            if len(asm_codes) >= max_asm_lines:
                break

            # 更新上下文游标
            left_index -= 1

        # 如果有右边的，再添加右边的
        if right_index < len(right_raw_data_items):
            # 添加
            asm_codes.extend(right_raw_data_items[0]["asm_lines"])

            # 如果超过了50，就不添加了
            if len(asm_codes) >= max_asm_lines:
                break

            # 更新上下文游标
            right_index += 1

        # 如果左右都没有了，就退出
        if left_index < 0 and right_index >= len(right_raw_data_items):
            break
    return answer_start_index, answer_end_index, answer_length, asm_codes


def check_effective(src_codes, asm_codes):
    effective_src_codes_num = 0
    for src_code in src_codes:
        if len(src_code.split()) > 1:
            effective_src_codes_num += 1
    if effective_src_codes_num < 3:
        return False

    return True
