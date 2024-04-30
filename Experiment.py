import copy
import difflib
import multiprocessing
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Pool
from typing import List

from loguru import logger
from tqdm import tqdm

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import analyze_src_codes
from experiments import tc_manager
from experiments.model_manager import init_models
from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file
from main.interface import DataItemForFunctionConfirmModel, DataItemForCodeSnippetPositioningModel, \
    DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.new_model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.new_model_application import SnippetPositioner
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin, VulFunctionPatch

# 获取当前时间并格式化为字符串，例如 '20230418_101530'
start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
logger.remove()
logger.add(sys.stdout, level="SUCCESS")
# 添加日志处理器，文件名包含脚本开始时间
logger.add(f"logs/experiment_{start_time}.log", level="SUCCESS")


def is_reserved_function_name(function_name):
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


def generate_model_input(asm_function, vul_function: VulFunction):
    # 过滤条件 1：保留函数名
    if is_reserved_function_name(asm_function.function_name):
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


def generate_model_input_wrapper(args):
    asm_function, vul_function = args
    return generate_model_input(asm_function, vul_function)


def cal_similarity(asm_codes_1, asm_codes_2):
    s1 = " ".join(asm_codes_1[:40])
    s2 = " ".join(asm_codes_2[:40])
    similarity = difflib.SequenceMatcher(None, s1, s2).quick_ratio()
    return similarity


def filter_and_generate_data_items(asm_function_dict, vul_functions: List[VulFunction]):
    found_functions = []
    data_items = []
    tasks = [(asm_function, vul_function)
             for vul_function in vul_functions
             for asm_function in asm_function_dict.values()]
    with Pool() as pool:
        results = pool.imap_unordered(generate_model_input_wrapper, tasks)
        for data_item in tqdm(results, f"filter_and_generate_data_items", total=len(tasks)):
            if data_item is None:
                continue
            data_items.append(data_item)
            if data_item.function_name == data_item.bin_function_name:
                found_functions.append(data_item.bin_function_name)
    logger.success(f"filter: {len(tasks)} ---> {len(data_items)}")
    return data_items, found_functions


def extract_asm_functions(asm_functions_cache, test_bin):
    if test_bin.binary_path not in asm_functions_cache:
        asm_function_dict = parse_objdump_file(test_bin.binary_path, ignore_warnings=True)
        asm_functions_cache[test_bin.binary_path] = asm_function_dict
    else:
        asm_function_dict = asm_functions_cache[test_bin.binary_path]
    return asm_function_dict


def check_result(tc: VulConfirmTC, confirmed_function_name: str, analysis):
    ground_truth = tc.ground_truth
    # 如果ground truth中有漏洞
    if ground_truth.contained_vul_function_names:
        # 没有确认到漏洞，FN
        if confirmed_function_name is None:
            analysis.fn += 1
            logger.info(f"\t\tcheck result: FN")
        else:
            vul_function_names = [func.get_function_name() for func in tc.vul_functions]
            # 确认到正确漏洞函数，TP
            if confirmed_function_name in vul_function_names:
                analysis.tp += 1
                logger.info(f"\t\tcheck result: TP")
            # 确认到错误漏洞函数，FP, FN
            else:
                analysis.fp += 1
                analysis.fn += 1
                logger.info(f"\t\tcheck result: FP, FN")
    # 如果ground truth中不包含漏洞函数名
    else:
        # 没有确认到漏洞，TN
        if confirmed_function_name is None:
            analysis.tn += 1
            logger.info(f"\t\tcheck result: TN")
        # 确认到漏洞，FP
        else:
            analysis.fp += 1
            logger.info(f"\t\tcheck result: FP")
    logger.info("\n")


@dataclass
class Analysis:
    over_filter_count: int = 0
    model_1_find_count: int = 0
    model_1_2_find_count: int = 0
    model_1_2_precisely_find_count: int = 0
    model_3_find_count: int = 0
    tp: int = 0  # True Positives
    fp: int = 0  # False Positives
    tn: int = 0  # True Negatives
    fn: int = 0  # False Negatives

    @property
    def total(self):
        return self.tp + self.tn + self.fp + self.fn

    @property
    def precision(self):
        return self.tp / (self.tp + self.fp) if self.tp + self.fp > 0 else 0

    @property
    def recall(self):
        return self.tp / (self.tp + self.fn) if self.tp + self.fn > 0 else 0

    @property
    def f1(self):
        precision = self.precision
        recall = self.recall
        return 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0

    @property
    def accuracy(self):
        total = self.total
        return (self.tp + self.tn) / total if total > 0 else 0

    @property
    def specificity(self):
        return self.tn / (self.tn + self.fp) if self.tn + self.fp > 0 else 0

    @property
    def error_rate(self):
        total = self.total
        return (self.fp + self.fn) / total if total > 0 else 0

    @property
    def mcc(self):
        # Matthews Correlation Coefficient calculation
        numerator = (self.tp * self.tn - self.fp * self.fn)
        denominator = ((self.tp + self.fp) * (self.tp + self.fn) *
                       (self.tn + self.fp) * (self.tn + self.fn)) ** 0.5
        return numerator / denominator if denominator != 0 else 0


def parse_objdump_file_wrapper(file_path):
    asm_function_dict = parse_objdump_file(file_path, ignore_warnings=True)
    return file_path, asm_function_dict


def generate_asm_function_cache(tcs):
    path_set = set()
    for tc in tcs:
        path_set.add(tc.test_bin.binary_path)

    paths = list(path_set)

    cache_dict = {}
    with Pool(multiprocessing.cpu_count() - 6) as pool:
        results = list(tqdm(pool.imap_unordered(parse_objdump_file_wrapper, paths), total=len(paths),
                            desc="generate_asm_function_cache"))

    for path, asm_function_dict in results:
        cache_dict[path] = asm_function_dict

    return cache_dict


def confirm_functions(model, tc: VulConfirmTC, analysis: Analysis, asm_functions_cache: dict, prob_threshold=0.99):
    """
    函数确认
    """
    vul_functions: List[VulFunction] = tc.vul_functions
    test_bin: TestBin = tc.test_bin

    # 1. 提取汇编函数
    logger.info(f"\textracting asm functions from {test_bin.binary_path}")
    asm_function_dict = extract_asm_functions(asm_functions_cache, test_bin)
    logger.info(f"\t\textracted {len(asm_function_dict)} asm functions")

    # 2. 过滤asm函数并生成模型输入数据
    filter_find_flag = False
    logger.info(f"\t\tfilter asm functions and generating model input data...")
    data_items, found_vul_functions = filter_and_generate_data_items(asm_function_dict, vul_functions)
    logger.info(f"\t\tgenerated {len(data_items)} data items")

    logger.success(f"\tvul function names: {[vf.function_name for vf in vul_functions]}")
    logger.success(f"\tbin vul function names: {tc.ground_truth.contained_vul_function_names}")
    logger.success(f"\tfound vul function names: {found_vul_functions}")
    if found_vul_functions:
        filter_find_flag = True
    else:
        analysis.over_filter_count += 1

    # 3. 调用模型
    predictions = model.confirm(data_items)

    # 4. 确认结果
    logger.info(f"\tconfirmed functions:")
    model_1_find_flag = False
    confirmed_items = []
    for data_item, (pred, prob) in zip(data_items, predictions):
        if pred == 1 and prob > prob_threshold:
            confirmed_items.append((data_item, prob))

            # 预览结果
            print_info = f"{data_item.function_name} {data_item.bin_function_name}\t{prob}\t{data_item.asm_codes}"
            if data_item.get_src_function_name() == data_item.bin_function_name:
                print_info = f"\t**** {print_info}"
                model_1_find_flag = True
            else:
                print_info = f"\t\t{print_info}"
            logger.info(print_info)
        elif data_item.get_src_function_name() == data_item.bin_function_name:
            print_info = f"{data_item.function_name} {data_item.bin_function_name}\t{prob}\t{data_item.asm_codes}"
            print_info = f"\tmodel 1 missed: xxxx {print_info}"
            logger.warning(print_info)
    if model_1_find_flag:
        analysis.model_1_find_count += 1

    # 5. ground truth
    logger.info(f"\tground truth: ")
    logger.info(f"\t\tvul: {tc.public_id}")
    logger.info(f"\t\tvul functions: {[func.function_name for func in tc.vul_functions]}")
    logger.info(f"\t\ttest_bin: {tc.test_bin.library_name} {tc.test_bin.version_tag} {tc.test_bin.binary_name}")
    logger.info(f"\t\tbin vul functions: {tc.ground_truth.contained_vul_function_names}")
    logger.info(f"\t\tis vul fixed: {tc.ground_truth.is_fixed}")

    # 构成返回值
    confirmed_function_dict = {}
    vul_function_dict = {vf.get_function_name(): vf for vf in vul_functions}
    for item, prob in sorted(confirmed_items, key=lambda x: x[1], reverse=True):
        # 漏洞函数，二进制函数名，汇编代码
        function_name = item.get_src_function_name()
        if function_name not in confirmed_function_dict:
            confirmed_function_dict[function_name] = []
        confirmed_function_dict[function_name].append(
            (vul_function_dict[function_name], item.bin_function_name, item.asm_codes))
    return confirmed_function_dict, filter_find_flag, model_1_find_flag


def split_list_by_sliding_window(input_list, window_length=70, step=20):
    # 初始化一个空列表来存放所有窗口
    windows = []

    # 如果输入列表长度小于等于窗口长度，直接返回
    if len(input_list) <= window_length:
        return [input_list]

    # 滑动窗口
    window_end = window_length
    while True:
        windows.append(input_list[window_end - window_length:window_end])
        if window_end + step > len(input_list):
            break
        window_end += step

    # 如果最后一个窗口的长度不足，补齐
    if window_end < len(input_list):
        windows.append(input_list[-window_length:])

    return windows


def locate_snippet(locate_model: SnippetPositioner, function_name, patch: VulFunctionPatch,
                   normalized_asm_codes: List[str]):
    """
    片段定位
    """
    # 滑动窗口
    asm_codes_windows = split_list_by_sliding_window(normalized_asm_codes)
    logger.info(f"asm codes length: {len(normalized_asm_codes)}, window num: {len(asm_codes_windows)}")

    # 生成模型输入：漏洞片段的前5行有效代码 + 汇编代码窗口
    start_data_items = []
    above_context = []
    for window in asm_codes_windows:
        start_data_item = DataItemForCodeSnippetPositioningModel(function_name=function_name,
                                                                 src_codes=patch.vul_snippet_codes,
                                                                 asm_codes=window)
        start_data_item.normalize_src_codes()
        start_data_item.is_normalized = True
        start_data_item.src_codes = above_context = start_data_item.src_codes[:10]
        start_data_items.append(start_data_item)

    # 定位
    start_predictions = locate_model.locate(start_data_items)

    # 找到最大概率的片段
    start_asm_codes_str, start_asm_codes_prob = max(start_predictions, key=lambda x: x[1])
    logger.info(f"vul snippet src codes start:\t{above_context}")
    logger.info(f"\tlocate prob: {start_asm_codes_prob}")
    logger.info(f"\tlocated asm codes: {start_asm_codes_str}")
    if not start_asm_codes_str:
        return [], 0

    # 找到定位的片段在原始汇编代码中的位置
    start_index = 0
    while start_asm_codes_str in " ".join(normalized_asm_codes[start_index:]) and start_index < len(
            normalized_asm_codes):
        start_index += 1
    start_index -= 1

    # 最终定位结果
    snippet = normalized_asm_codes[start_index:start_index + 50]

    return snippet, start_asm_codes_prob


def find_minimal_containing_slice(str_list, sub_str):
    n = len(str_list)
    start, end = 0, n  # 初始化起始和终止指针

    # 缩减左侧边界
    while start < n:
        if sub_str in " ".join(str_list[start:end]):
            start += 1
        else:
            start -= 1
            break

    # 修正越界情况
    start = max(start - 1, 0)

    # 缩减右侧边界
    while end > start:
        if sub_str in " ".join(str_list[start:end]):
            end -= 1
        else:
            end += 1
            break

    # 修正越界情况
    end = min(end + 1, n)

    # 返回最小切片
    return str_list[start:end]


def _judge_is_fixed(choice_model: SnippetChoicer,
                    function_name,
                    patches: List[VulFunctionPatch],
                    normalized_asm_codes_snippet_list: List[List[str]]):
    logger.success(f"\tjudge is fixed: {function_name}, patch num: {len(patches)}")
    # 生成模型输入
    data_items: List[DataItemForCodeSnippetConfirmModelMC] = []
    for patch, normalized_asm_codes_snippet in zip(patches, normalized_asm_codes_snippet_list):
        data_item = DataItemForCodeSnippetConfirmModelMC(function_name=function_name,
                                                         asm_codes=normalized_asm_codes_snippet,
                                                         src_codes_0=patch.vul_snippet_codes,
                                                         src_codes_1=patch.fixed_snippet_codes)
        data_item.normalized_str_codes()
        data_item.is_normalized = True
        data_items.append(data_item)

    # 批量确认
    predictions = choice_model.choice(data_items)

    # 根据概率
    vul_prob = 0
    fix_prob = 0
    for data_item, ((choice_0, choice_0_prob), (choice_1, choice_1_prob)) in zip(data_items, predictions):
        logger.success(f"\tquestion: {data_item.get_question_text()}")
        logger.success(f"\tvul src codes:\t\t{choice_0_prob}\t{data_item.get_src_codes_0_text()}")
        logger.success(f"\tfixed src codes:\t{choice_1_prob}\t{data_item.get_src_codes_1_text()}")
        logger.success(f"\t\t patch choice result: vul prob: {choice_0_prob}, fix prob: {choice_1_prob}")
        vul_prob += choice_0_prob
        fix_prob += choice_1_prob
    logger.success(f"\t\tchoice result: vul prob: {vul_prob}, fix prob: {fix_prob}")

    return vul_prob, fix_prob


def run_tc(choice_model, confirm_model, locate_model, tc: VulConfirmTC, analysis: Analysis, asm_functions_cache):
    has_vul_function = False
    has_vul = False
    is_fixed = False
    # step 1: locate vul function
    confirmed_function_dict, filter_find_flag, model_1_find_flag = confirm_functions(confirm_model,
                                                                                     tc,
                                                                                     analysis,
                                                                                     asm_functions_cache)
    # step 2: locate and filter
    all_count, confirmed_results, model_1_2_find_flag, precisely_find_flag = locate_snippets(analysis,
                                                                                             confirmed_function_dict,
                                                                                             locate_model)
    logger.success(f"located functions: {all_count} ---> {len(confirmed_results)}")
    logger.success(
        f"confirm summary: {filter_find_flag} {model_1_find_flag} {model_1_2_find_flag} {precisely_find_flag}")

    # step 3: 判断是否已经修复
    if confirmed_results:
        vul_prob, fix_prob, has_vul_function, has_vul, is_fixed = judge_located_snippets(choice_model,
                                                                                         confirmed_results,
                                                                                         has_vul,
                                                                                         has_vul_function)
        if is_fixed == tc.is_fixed():
            analysis.model_3_find_count += 1
        logger.success(f"vul prob: {vul_prob}, fix prob: {fix_prob}")

    # step 4: 检查结果
    if tc.has_vul():
        if has_vul:
            analysis.tp += 1
            tc_conclusion = 'TP'
        else:
            analysis.fn += 1
            tc_conclusion = 'FN'
    else:
        if has_vul:
            analysis.fp += 1
            tc_conclusion = 'FP'
        else:
            analysis.tn += 1
            tc_conclusion = 'TN'
    logger.success(f"\ttc summary: ")
    logger.success(
        f"\t\tground truth:\thas_vul: {tc.has_vul()}, has_vul_function: {tc.has_vul_function()}, is_fixed: {tc.is_fixed()}")
    logger.success(
        f"\t\tconfirm result:\thas_vul: {has_vul}, has_vul_function: {has_vul_function}, is_fixed: {is_fixed}")
    logger.success(f"\t\tconclusion: {tc_conclusion}")


def judge_located_snippets(choice_model, confirmed_results, has_vul, has_vul_function):
    vul_prob = 0.0
    fix_prob = 0.0
    is_fixed = None
    for vul_function_name, bin_function_name, locate_prob, succeed_locate_patches, normalized_asm_codes_snippet_list in confirmed_results:
        cur_vul_prob, cur_fix_prob = _judge_is_fixed(choice_model,
                                                     vul_function_name,
                                                     succeed_locate_patches,
                                                     normalized_asm_codes_snippet_list)
        vul_prob += cur_vul_prob
        fix_prob += cur_fix_prob
    if confirmed_results:
        has_vul_function = True
        if vul_prob > fix_prob:
            is_fixed = False
            has_vul = True
        else:
            is_fixed = True
            has_vul = False
    return vul_prob, fix_prob, has_vul_function, has_vul, is_fixed


def locate_snippets(analysis, confirmed_function_dict, locate_model):
    all_count = 0
    confirmed_results = []
    for i, (vul_function_name, results) in enumerate(confirmed_function_dict.items(), 1):
        all_count += len(results)
        tmp_results = []
        tmp_confirmed_results = []
        for confirmed_vul_function, bin_function_name, confirmed_normalized_asm_codes in results:
            succeed_locate_patches = []
            normalized_asm_codes_snippet_list = []
            prob_list = []
            for patch in confirmed_vul_function.patches:
                # locate snippet
                normalized_asm_codes_snippet, start_asm_codes_prob = locate_snippet(locate_model,
                                                                                    confirmed_vul_function.get_function_name(),
                                                                                    patch,
                                                                                    confirmed_normalized_asm_codes)

                prob_list.append(start_asm_codes_prob)
                # if start_asm_codes_prob > 0.9 and normalized_asm_codes_snippet:
                if normalized_asm_codes_snippet:
                    succeed_locate_patches.append(patch)
                    normalized_asm_codes_snippet_list.append(normalized_asm_codes_snippet)

            # 汇总函数确认结果，用于分析
            avg_prob = sum(prob_list) / len(prob_list)
            # 如果只有一个，直接用
            if len(results) == 1:
                tmp_confirmed_results.append((vul_function_name,
                                              bin_function_name,
                                              avg_prob,
                                              succeed_locate_patches,
                                              normalized_asm_codes_snippet_list))
            else:
                # 如果有多个，确认所有概率大于0.95的
                if avg_prob > 0.95:
                    tmp_confirmed_results.append((vul_function_name,
                                                  bin_function_name,
                                                  avg_prob,
                                                  succeed_locate_patches,
                                                  normalized_asm_codes_snippet_list))
                # 全部添加至临时结果
                tmp_results.append((vul_function_name,
                                    bin_function_name,
                                    avg_prob,
                                    succeed_locate_patches,
                                    normalized_asm_codes_snippet_list))

        # 如果没有确认到，取最大的
        if not tmp_confirmed_results and tmp_results:
            tmp_confirmed_results = [max(tmp_results, key=lambda x: x[2])]

        # 排序
        tmp_confirmed_results = sorted(tmp_confirmed_results, key=lambda x: x[2], reverse=True)[:3]
        confirmed_results.extend(tmp_confirmed_results)

    # 检查确认结果
    model_1_2_find_flag = False
    find_false_flag = False
    precisely_find_flag = False
    for vul_function_name, bin_function_name, prob, _, _ in confirmed_results:
        if vul_function_name == bin_function_name:
            model_1_2_find_flag = True
            logger.success(f"located functions: ***** , {prob}, {vul_function_name} ---> {bin_function_name}")
        else:
            find_false_flag = True
            logger.warning(f"located functions: xxxxx , {prob}, {vul_function_name} ---> {bin_function_name}")
    if model_1_2_find_flag:
        analysis.model_1_2_find_count += 1
        if not find_false_flag:
            precisely_find_flag = True
            analysis.model_1_2_precisely_find_count += 1
    return all_count, confirmed_results, model_1_2_find_flag, precisely_find_flag


def run_experiment():
    # init models
    model_save_path = r"Resources/model_weights/model_1_weights_back_4.pth"
    model_2_save_path = r"Resources/model_weights/model_2_weights_back.pth"
    model_3_save_path = r"Resources/model_weights/model_3_weights_back_up.pth"
    confirm_model, choice_model, locate_model = init_models(model_2_save_path, model_3_save_path, model_save_path)

    # load test_cases
    tc_json_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    test_cases = tc_manager.load_test_cases(tc_json_path)

    # experiment test cases
    test_cases = [tc for tc in test_cases if not tc.has_vul_function()][:10]
    logger.success(f"Experiment tc num: {len(test_cases)}")

    analysis = Analysis()
    start = 0
    batch_size = 20
    total = 0
    while start < len(test_cases):
        test_cases_batch = test_cases[start:start + batch_size]
        total += len(test_cases_batch)
        asm_functions_cache = generate_asm_function_cache(test_cases_batch)
        logger.success(f"asm functions cache generated")

        for i, tc in enumerate(test_cases_batch, start + 1):
            logger.success(f"confirm tc: {i} {tc.public_id}")
            run_tc(choice_model, confirm_model, locate_model, tc, analysis, asm_functions_cache)

        # 预览阶段结果
        logger.success(f"test result:")
        logger.success(f"\ttotal: {total}")
        logger.success(
            f"over filter count: {analysis.over_filter_count}, {round((analysis.over_filter_count / total) * 100, 2)}%")
        logger.success(
            f"model 1 find count: {analysis.model_1_find_count}, {round((analysis.model_1_find_count / total) * 100, 2)}%")
        logger.success(
            f"model 1 and 2 find count: {analysis.model_1_2_find_count}, {round((analysis.model_1_2_find_count / total) * 100, 2)}%")
        logger.success(
            f"model 1 and 2 precisely find count: {analysis.model_1_2_precisely_find_count}, {round((analysis.model_1_2_precisely_find_count / total) * 100, 2)}%")
        logger.success(
            f"model 3 find count: {analysis.model_3_find_count}, {round((analysis.model_3_find_count / total) * 100, 2)}%")
        logger.success(f"\ttp: {analysis.tp}, fp: {analysis.fp}, tn: {analysis.tn}, fn: {analysis.fn}")
        logger.success(f"\tprecision: {analysis.precision}")
        logger.success(f"\trecall: {analysis.recall}")
        logger.success(f"\tf1: {analysis.f1}")
        logger.success(f"\taccuracy: {analysis.accuracy}")

        start += batch_size
    logger.success(f"all done.")


if __name__ == '__main__':
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    run_experiment()

    """
    目标：Less False Positive
    
    2. 
    """
