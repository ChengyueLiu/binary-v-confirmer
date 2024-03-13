import copy
import json
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
                                         train_data_json_file,
                                         min_src_lines=5,
                                         max_asm_lines=5):
    # openssl, libcrypto, libssl
    test_path, train_path, valid_path = find_files_in_dir(raw_train_data_json_dir, ".json")
    raw_train_data = load_from_json_file(train_path)
    # raw_valid_data = load_from_json_file(valid_path)
    # raw_test_data = load_from_json_file(test_path)

    train_data = _convert_to_train_data(raw_train_data, min_src_lines, max_asm_lines)
    # valid_data = _convert_to_train_data(raw_valid_data, min_src_lines, max_asm_lines)
    # test_data = _convert_to_train_data(raw_test_data, min_src_lines, max_asm_lines)

    save_to_json_file([train_data_item.custom_serialize() for train_data_item  in train_data], train_data_json_file)


def _convert_to_train_data(raw_train_data, min_src_lines, max_asm_lines, asm_src_ratio_limit=7):
    # 先找出来可能作为训练数据的函数源代码片段
    tmp_list = []
    for function_name, raw_train_data_items in raw_train_data.items():
        # step 1: 先找出这个函数完整的汇编代码，这个是answer context
        all_asm_codes = []
        for raw_train_data_item in raw_train_data_items:
            all_asm_codes.extend(raw_train_data_item['asm_lines'])

        # step 2: 然后截取一个随机长度的片段，作为question和answer
        src_line_num = random.randint(min_src_lines, max_asm_lines)
        if len(raw_train_data_items) < src_line_num:
            current_raw_train_data_items = raw_train_data_items
            tmp_list.append((function_name, all_asm_codes, current_raw_train_data_items))
        else:
            # TODO 这里随机选取片段的时候，多选几个片段，不然训练数据太少了。可以每10行选一个。
            count = 0
            start_left_border = 0
            start_right_border = start_left_border + src_line_num
            while start_right_border < len(raw_train_data_items) - src_line_num and count < 10:
                start = random.randint(start_left_border, start_right_border)
                end = start + src_line_num
                current_raw_train_data_items = raw_train_data_items[start:end]
                tmp_list.append((function_name, all_asm_codes, current_raw_train_data_items))

                count += 1
                start_right_border = start_right_border + src_line_num

    # 遍历这些片段，构成训练数据
    train_data_items = []
    biggest_ratio = 0
    ratio_lt_6 = 0
    ratio_lt_10 = 0
    for function_name, all_asm_codes, current_raw_train_data_items in tmp_list:
        # step 3: 构成训练数据
        current_asm_codes = []
        current_src_codes = []
        current_src_line_num = []
        current_sub_function_names = []
        for raw_train_data_item in current_raw_train_data_items:
            current_asm_codes.extend(raw_train_data_item['asm_lines'])
            if (raw_train_data_item['is_discriminator']
                    and current_src_line_num
                    and raw_train_data_item['line_number'] == current_src_line_num[-1]):
                continue
            else:
                current_src_codes.append(raw_train_data_item['current_src_line'])
                current_src_line_num.append(raw_train_data_item['line_number'])
                current_sub_function_names.append(raw_train_data_item['sub_function_name'])
        if len(set(current_sub_function_names)) != 1:
            has_in_line_code = True
        else:
            has_in_line_code = False

        # step 4: 筛选数据
        # 有效行数太少，跳过
        effective_src_lines = [line for line in current_src_codes if len(line.split()) >= 2]
        if len(effective_src_lines) < 3:
            continue

        # 源代码乱序的，或者两行之间相差太大的，跳过
        shuffle_flag = False
        last_num = current_src_line_num[0]
        for num in current_src_line_num:
            if num < last_num:
                shuffle_flag = True
                break
            elif num - last_num > 2:
                shuffle_flag = True
                break
            last_num = num
        if shuffle_flag:
            continue

        if current_src_codes:
            # 继续筛选
            ratio = len(current_asm_codes) / len(current_src_codes)
            if ratio > asm_src_ratio_limit:
                continue

            # 去掉汇编代码中无用的部分
            current_asm_codes = [line.split("\t")[-1] for line in current_asm_codes if len(line.split("\t")) == 3]
            all_asm_codes = [line.split("\t")[-1] for line in all_asm_codes if len(line.split("\t")) == 3]
            # {
            #     "function_name": function_name,
            #     "sub_function_name": current_sub_function_names[0],
            #     "has_in_line_code": has_in_line_code,
            #     "src_line_num": current_src_line_num,
            #     "src_codes": current_src_codes,
            #     "asm_length": f"{len(all_asm_codes)} -> {len(current_asm_codes)}",
            #     "asm_codes": current_asm_codes,
            #     "all_asm_codes": all_asm_codes
            # }
            train_data_items.append(DataItemForCodeSnippetPositioningModel(
                function_name=function_name,
                sub_function_name=current_sub_function_names[0],
                has_in_line_code=has_in_line_code,
                src_line_nums=current_src_line_num,
                src_codes=current_src_codes,
                asm_length=f"{len(all_asm_codes)} -> {len(current_asm_codes)}",
                asm_codes=current_asm_codes,
                all_asm_codes=all_asm_codes
            ))

            if ratio < 6:
                ratio_lt_6 += 1
            if ratio < 10:
                ratio_lt_10 += 1
            if ratio > biggest_ratio:
                biggest_ratio = ratio
                print(function_name, ratio, len(current_asm_codes), len(current_src_codes), len(all_asm_codes))
    print(len(train_data_items), ratio_lt_6, ratio_lt_10)
    return train_data_items
