import difflib
from datetime import datetime
from multiprocessing import Pool
from typing import List

from loguru import logger

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import analyze_src_codes
from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file
from main.interface import DataItemForFunctionConfirmModel
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin

# 获取当前时间并格式化为字符串，例如 '20230418_101530'
start_time = datetime.now().strftime("%Y%m%d_%H%M%S")

# 添加日志处理器，文件名包含脚本开始时间
logger.add(f"logs/experiment_{start_time}.log", level="INFO")


def load_test_cases(tc_save_path) -> List[VulConfirmTC]:
    """
    加载测试用例
    """
    test_cases = load_from_json_file(tc_save_path)
    test_cases = [VulConfirmTC.init_from_dict(tc) for tc in test_cases]
    return test_cases


def generate_model_input(asm_function, vul_function):
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

    # 过滤条件 1：参数数量检验
    asm_body_start_index, asm_param_count = analyze_asm_codes(data_item.asm_codes)
    src_body_start_index, src_param_count = analyze_src_codes(data_item.src_codes)
    if asm_param_count != src_param_count:
        return None

    # 截去函数定义和参数部分
    data_item.asm_codes = data_item.asm_codes[asm_body_start_index:]
    data_item.src_codes = data_item.src_codes[src_body_start_index:]

    return data_item


def generate_model_input_wrapper(args):
    asm_function, vul_function = args
    return generate_model_input(asm_function, vul_function)


def cal_similarity(asm_codes_1, asm_codes_2):
    s1 = " ".join(asm_codes_1[:40])
    s2 = " ".join(asm_codes_2[:40])
    similarity = difflib.SequenceMatcher(None, s1, s2).quick_ratio()
    return similarity


def confirm_functions(model, tc: VulConfirmTC, asm_functions_cache: dict):
    """
    函数确认
    """
    vul_functions: List[VulFunction] = tc.vul_functions
    test_bin: TestBin = tc.test_bin

    # 1. 提取汇编函数
    logger.info(f"\textracting asm functions from {test_bin.binary_path}")
    if test_bin.binary_path not in asm_functions_cache:
        asm_function_dict = parse_objdump_file(test_bin.binary_path, ignore_warnings=True)
        asm_functions_cache[test_bin.binary_path] = asm_function_dict
    else:
        asm_function_dict = asm_functions_cache[test_bin.binary_path]
    logger.info(f"\t\textracted {len(asm_function_dict)} asm functions")

    # 2. 过滤asm函数并生成模型输入数据
    logger.info(f"\t\tfilter asm functions and generating model input data...")
    found_functions = []
    data_items = []
    tasks = [(asm_function, vul_function)
             for vul_function in vul_functions
             for asm_function in asm_function_dict.values()]
    with Pool() as pool:
        results = pool.imap_unordered(generate_model_input_wrapper, tasks)
        for data_item in results:
            if data_item is None:
                continue
            data_items.append(data_item)
            if data_item.function_name.strip("*") == data_item.bin_function_name:
                found_functions.append(data_item.bin_function_name)
    logger.info(f"\t\tgenerated {len(data_items)} data items")
    logger.info(f"\t\tvul functions: {[vf.function_name for vf in vul_functions]}")
    logger.info(f"\t\tvul functions in data items: {found_functions}")

    # 3. 调用模型
    predictions = model.confirm(data_items)

    # 4. 预览ground truth
    logger.info(f"\tground truth: ")
    logger.info(f"\t\tvul: {tc.public_id}")
    logger.info(f"\t\tvul functions: {[func.function_name for func in tc.vul_functions]}")
    logger.info(f"\t\ttest_bin: {tc.test_bin.library_name} {tc.test_bin.version_tag} {tc.test_bin.binary_name}")
    logger.info(f"\t\tbin vul functions: {tc.ground_truth.contained_vul_function_names}")
    logger.info(f"\t\tis vul fixed: {tc.ground_truth.is_fixed}")

    # 5. 确认结果
    logger.info(f"\tconfirmed functions:")
    confirmed_function_name = None
    confirmed_prob = 0
    asm_codes_list = []
    for data_item, (pred, prob) in zip(data_items, predictions):
        prob = round(prob, 4)
        if pred == 1 and prob > 0.95:
            if prob > confirmed_prob:
                confirmed_function_name = data_item.bin_function_name
                confirmed_prob = prob

            # 预览结果
            src_function_name = data_item.function_name
            if src_function_name.startswith("*"):
                src_function_name = src_function_name[1:]
            if src_function_name == data_item.bin_function_name:
                logger.info(f"\t**** {data_item.function_name} {data_item.bin_function_name} {prob} ****")
            else:
                logger.info(f'\t\t {data_item.function_name} {data_item.bin_function_name} {prob}')
            asm_codes_list.append(data_item.asm_codes[:40])
        else:
            src_function_name = data_item.function_name
            if src_function_name.startswith("*"):
                src_function_name = src_function_name[1:]
            if src_function_name == data_item.bin_function_name:
                logger.info(f"\txxxx {data_item.function_name} {data_item.bin_function_name} {prob} xxxx")
                asm_codes_list.append(data_item.asm_codes[:40])
    logger.info(f"\tasm codes:")
    for asm_codes in asm_codes_list:
        logger.info(f"\t\t{asm_codes}")

    return confirmed_function_name, confirmed_prob


def analyze_result(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0
    logger.info(f"test result:")
    logger.info(f"\ttp: {tp} fp: {fp} fn: {fn}")
    logger.info(f"\tprecision: {precision}")
    logger.info(f"\trecall: {recall}")
    logger.info(f"\tf1: {f1}")


def check_result(ground_truth, confirmed_function_name):
    tp, fp, fn = 0, 0, 0
    # 如果ground truth中包含漏洞函数名
    if ground_truth.contained_vul_function_names:
        if confirmed_function_name is None:
            fn += 1
            logger.info(f"check result: FN")
        else:
            if confirmed_function_name in ground_truth.contained_vul_function_names:
                tp += 1
                logger.info(f"check result: TP")
            else:
                fp += 1
                logger.info(f"check result: FP")
    # 如果ground truth中不包含漏洞函数名
    else:
        if confirmed_function_name is None:
            tp += 1
            logger.info(f"check result: TP")
        else:
            fp += 1
            logger.info(f"check result: FP")
    logger.info("\n")
    return tp, fp, fn


def run_experiment():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    model_save_path = r"Resources/model_weights/model_1_weights.pth"

    logger.info(f"init model...")
    model = FunctionConfirmer(model_save_path=model_save_path, batch_size=128)

    logger.info(f"load test cases from {tc_save_path}")
    test_cases = load_test_cases(tc_save_path)
    logger.info(f"loaded {len(test_cases)} test cases")
    test_cases = [tc for tc in test_cases if tc.is_effective()]
    logger.info(f"include {len(test_cases)} effective test cases")

    # 分开测试的话，筛选一下
    # # 不包含漏洞的测试用例
    # test_cases = [tc for tc in test_cases
    #               if not tc.ground_truth.contained_vul_function_names]
    # # 包含，且没修复
    # test_case = [tc for tc in test_cases
    #              if tc.ground_truth.contained_vul_function_names and not tc.ground_truth.is_fixed]
    #
    # # 包含，且已修复
    # test_case = [tc for tc in test_cases
    #              if tc.ground_truth.contained_vul_function_names and tc.ground_truth.is_fixed]

    asm_functions_cache = {}
    tp = 0
    fp = 0
    fn = 0
    for i, tc in enumerate(test_cases[390:400], 1):
        logger.info(f"confirm: {i} {tc.public_id}")
        ground_truth = tc.ground_truth
        confirmed_function_name, confirmed_prob = confirm_functions(model, tc, asm_functions_cache)
        tp, fp, fn = check_result(ground_truth, confirmed_function_name)

    logger.info(f"test result:")
    logger.info(f"\ttc num: {len(test_cases)}")
    analyze_result(tp, fp, fn)


if __name__ == '__main__':
    run_experiment()
