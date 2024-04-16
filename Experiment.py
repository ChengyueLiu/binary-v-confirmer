import os
from typing import List

import torch
from loguru import logger
from torch.utils.data import DataLoader
from transformers import RobertaTokenizer

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import analyze_src_codes
from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file
from main.interface import DataItemForFunctionConfirmModel
from main.models.function_confirm_model.dataset_and_data_provider import create_dataset_from_model_input
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin


def load_test_cases(tc_save_path) -> List[VulConfirmTC]:
    """
    加载测试用例
    """
    test_cases = load_from_json_file(tc_save_path)
    test_cases = [VulConfirmTC.init_from_dict(tc) for tc in test_cases]
    return test_cases


def confirm_functions(model, tc: VulConfirmTC):
    """
    函数确认
    """
    print(f"confirm: {tc.public_id}")
    vul_functions: List[VulFunction] = [func for func in tc.vul_functions if func.vul_source_codes]
    test_bin: TestBin = tc.test_bin
    if not vul_functions:
        print(f"TEST CASE {tc.public_id} HAS NO VUL FUNCTIONS, SKIPPED!")
        return

    # 生成数据
    data_items = []
    print(f"\textracting asm functions from {test_bin.binary_path}")
    asm_function_dict = parse_objdump_file(test_bin.binary_path, ignore_warnings=True)
    print(f"\textracted {len(asm_function_dict)} asm functions")

    print(f"\tgenerating model input data...")
    for vul_function in vul_functions:
        for asm_function in asm_function_dict.values():
            # 构成模型输入
            asm_codes, _ = asm_function.get_asm_codes()
            data_item = DataItemForFunctionConfirmModel(function_name=vul_function.function_name,
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

            # 过滤条件：参数数量检验
            asm_body_start_index, asm_param_count = analyze_asm_codes(data_item.asm_codes)
            src_body_start_index, src_param_count = analyze_src_codes(data_item.src_codes)
            if asm_param_count != src_param_count:
                if data_item.function_name.strip("*") == data_item.bin_function_name:
                    print(f"asm_param_count: {asm_param_count}, src_param_count: {src_param_count}")
                else:
                    continue

            # 截去函数定义和参数部分
            data_item.asm_codes = data_item.asm_codes[asm_body_start_index:]
            data_item.src_codes = data_item.src_codes[src_body_start_index:]
            data_items.append(data_item)
    print(f"\tgenerated {len(data_items)} data items")

    # 调用模型
    predictions = model.confirm(data_items)

    print(f"confirm result: \n"
          f"\tvul: {tc.public_id}\n"
          f"\tvul functions: {[func.function_name for func in tc.vul_functions]}\n"
          f"\ttest_bin: {tc.test_bin.library_name} {tc.test_bin.version_tag} {tc.test_bin.binary_name}\n"
          f"\tground truth: {tc.ground_truth.is_fixed} {tc.ground_truth.contained_vul_function_names}\n")
    print(f"\tconfirmed functions:")
    for data_item, (pred, prob) in zip(data_items, predictions):
        prob = round(prob, 4)
        if pred == 1 and prob > 0.95:
            function_name = data_item.function_name
            if function_name.startswith("*"):
                function_name = function_name[1:]
            if function_name == data_item.bin_function_name:
                print(f"\t***** {function_name} {data_item.bin_function_name} {prob} *****")
            else:
                print('\t\t', data_item.function_name, data_item.bin_function_name, prob)


def run_experiment():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    model_save_path = r"Resources/model_weights/model_1_weights.pth"

    print(f"init model...")
    model = FunctionConfirmer(model_save_path=model_save_path, batch_size=128)

    print(f"load test cases from {tc_save_path}")
    test_cases = load_test_cases(tc_save_path)

    for i, tc in enumerate(test_cases[:10], 1):
        if tc.public_id != "CVE-2012-2776":
            continue
        confirm_functions(model, tc)


if __name__ == '__main__':
    run_experiment()
