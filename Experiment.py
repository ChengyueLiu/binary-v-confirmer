import copy
import difflib
import multiprocessing
import os
import re
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Pool
from typing import List, Tuple

from loguru import logger
from tqdm import tqdm

from bintools.general.bin_tool import analyze_asm_codes
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import analyze_src_codes
from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file
from main.interface import DataItemForFunctionConfirmModel, DataItemForCodeSnippetPositioningModel, \
    DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.new_model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.new_model_application import SnippetPositioner
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin, VulFunctionPatch

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

    if vul_function.get_function_name() == asm_function.function_name:
        logger.info(f"\t\tfound vul function:")
        logger.info(f"\t\t\tfunction_name: {vul_function.get_function_name()}, {src_param_count}, {asm_param_count}")
        logger.info(f"\t\t\tsrc codes: {data_item.src_codes}")
        logger.info(f"\t\t\tasm codes: {data_item.asm_codes}")
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


def filter_and_generate_data_items(asm_function_dict, vul_functions: List[VulFunction]):
    found_functions = []
    data_items = []
    tasks = [(asm_function, vul_function)
             for vul_function in vul_functions
             for asm_function in asm_function_dict.values()]
    with Pool() as pool:
        results = pool.imap_unordered(generate_model_input_wrapper, tasks)
        for data_item in tqdm(results, f"filter_and_generate_data_items"):
            if data_item is None:
                continue
            data_items.append(data_item)
            if data_item.function_name == data_item.bin_function_name:
                found_functions.append(data_item.bin_function_name)
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


def confirm_functions(model, tc: VulConfirmTC, asm_functions_cache: dict, prob_threshold=0.99) -> List[
    Tuple[VulFunction, List[str]]]:
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
    logger.info(f"\t\tfilter asm functions and generating model input data...")
    data_items, found_functions = filter_and_generate_data_items(asm_function_dict, vul_functions)
    logger.info(f"\t\tgenerated {len(data_items)} data items")
    logger.info(f"\t\tvul functions: {[vf.function_name for vf in vul_functions]}")
    logger.info(f"\t\tvul functions in data items: {found_functions}")
    if len(tc.ground_truth.contained_vul_function_names) != len(found_functions):
        logger.warning(f"\t\t!!!!! vul functions not found in data items")
        logger.warning(f"\t\tcontained_vul_function_names: {tc.ground_truth.contained_vul_function_names}")

    # 3. 调用模型
    predictions = model.confirm(data_items)

    # 4. 确认结果
    logger.info(f"\tconfirmed functions:")
    confirmed_items = []
    for data_item, (pred, prob) in zip(data_items, predictions):
        if pred == 1 and prob > prob_threshold:
            confirmed_items.append(data_item)

            # 预览结果
            print_info = f"{data_item.function_name} {data_item.bin_function_name}\t{prob}\t{data_item.asm_codes}"
            if data_item.get_src_function_name() == data_item.bin_function_name:
                print_info = f"\t**** {print_info}"
            else:
                print_info = f"\t\t{print_info}"
            logger.info(print_info)
        elif data_item.get_src_function_name() == data_item.bin_function_name:
            print_info = f"{data_item.function_name} {data_item.bin_function_name}\t{prob}\t{data_item.asm_codes}"
            print_info = f"\txxxx {print_info}"
            logger.info(print_info)

    # 5. ground truth
    logger.info(f"\tground truth: ")
    logger.info(f"\t\tvul: {tc.public_id}")
    logger.info(f"\t\tvul functions: {[func.function_name for func in tc.vul_functions]}")
    logger.info(f"\t\ttest_bin: {tc.test_bin.library_name} {tc.test_bin.version_tag} {tc.test_bin.binary_name}")
    logger.info(f"\t\tbin vul functions: {tc.ground_truth.contained_vul_function_names}")
    logger.info(f"\t\tis vul fixed: {tc.ground_truth.is_fixed}")

    results = []
    vul_function_dict = {vf.get_function_name(): vf for vf in vul_functions}
    for item in confirmed_items:
        results.append((vul_function_dict[item.get_src_function_name()], item.asm_codes))

    return results


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
                   normalized_asm_codes: List[str]) -> List[str]:
    """
    片段定位
    """
    # 滑动窗口
    asm_codes_windows = split_list_by_sliding_window(normalized_asm_codes)
    logger.info(f"asm codes length: {len(normalized_asm_codes)}, window num: {len(asm_codes_windows)}")

    # 分别定位开头和结尾
    # 开头至少要3行有效代码！开头比结尾更重要！
    # above_context = []
    # count = 0
    # for src_code in patch.vul_snippet_codes:
    #     above_context.append(src_code)
    #     if len(src_code.strip()) > 1:
    #         count += 1
    #     if count >= 3:
    #         break
    above_context = copy.deepcopy(patch.vul_snippet_codes[:3])
    below_context = copy.deepcopy(patch.vul_snippet_codes[-3:])
    start_data_items = []
    end_data_items = []
    for window in asm_codes_windows:
        start_data_item = DataItemForCodeSnippetPositioningModel(function_name=function_name,
                                                                 src_codes=above_context,
                                                                 asm_codes=window)
        start_data_item.normalize_src_codes()
        start_data_item.is_normalized = True
        start_data_items.append(start_data_item)

        end_data_item = DataItemForCodeSnippetPositioningModel(function_name=function_name,
                                                               src_codes=below_context,
                                                               asm_codes=window)
        end_data_item.normalize_src_codes()
        start_data_item.is_normalized = True
        end_data_items.append(end_data_item)

    # 处理结果
    all_data_items = start_data_items + end_data_items
    all_predictions = locate_model.locate(start_data_items + end_data_items)
    # logger.info(f"locate result: {len(all_data_items)} ---> {len(all_predictions)}")
    mid_index = len(all_predictions) // 2  # 获取中间索引，用于分割开头和结尾的预测结果
    start_predictions = all_predictions[:mid_index]
    end_predictions = all_predictions[mid_index:]

    # 找到最大概率的片段
    start_asm_codes_str, start_asm_codes_prob = max(start_predictions, key=lambda x: x[1])
    logger.info(f"start src codes: {above_context}")
    logger.info(f"\tpatch location start: {start_asm_codes_prob} {start_asm_codes_str}")

    end_asm_codes_str, end_asm_codes_prob = max(end_predictions, key=lambda x: x[1])
    logger.info(f"end src codes: {below_context}")
    logger.info(f"\tpatch location end: {end_asm_codes_prob} {end_asm_codes_str}")

    # 开始结束位置，都能大概率定位到才可以
    if not start_asm_codes_str or start_asm_codes_prob < 0.8:
        return None
    if not end_asm_codes_str or end_asm_codes_prob < 0.8:
        return None

    # 找到开始位置
    start_index = 0
    while start_asm_codes_str in " ".join(normalized_asm_codes[start_index:]):
        start_index += 1
    start_index -= 1

    # 找到结束位置
    end_index = len(normalized_asm_codes)
    while end_asm_codes_str in " ".join(normalized_asm_codes[:end_index]):
        end_index -= 1
    end_index += 1
    # TODO 结束位置应该在开始位置之后。
    logger.info(f"\toriginal start index: {start_index}, end index: {end_index}")
    if end_index - start_index < 20 or end_index - start_index > 50:
        end_index = start_index + 50
    # 取前50个汇编码指令
    snippet = normalized_asm_codes[start_index:end_index]

    logger.info(f"\tfinal start index: {start_index}, end index: {end_index}")
    logger.info(f"\tabove context src codes: {above_context}")
    logger.info(
        f"\tall asm length: {len(normalized_asm_codes)}, asm snippet length: {len(snippet)}, snippet: {snippet}")

    return snippet


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
    logger.info(f"\tjudge is fixed: {function_name}")
    for data_item, ((choice_0, choice_0_prob), (choice_1, choice_1_prob)) in zip(data_items, predictions):
        logger.info(f"\tquestion: {data_item.get_question_text()}")
        logger.info(f"\tvul src codes:   {choice_0_prob} {data_item.get_src_codes_0_text()}")
        logger.info(f"\tfixed src codes: {choice_1_prob} {data_item.get_src_codes_1_text()}")

        vul_prob += choice_0_prob
        fix_prob += choice_1_prob
    logger.info(f"\tchoice result: vul prob: {vul_prob}, fix prob: {fix_prob}")

    return fix_prob > vul_prob


def run_tc(choice_model, confirm_model, locate_model, tc: VulConfirmTC, analysis, asm_functions_cache):
    has_vul = False
    has_vul_function = False
    is_fixed = None

    # locate vul function
    results = confirm_functions(confirm_model, tc, asm_functions_cache)
    confirmed_function_num = len(results)
    for i, (confirmed_vul_function, confirmed_normalized_asm_codes) in enumerate(results, 1):
        # locate vul snippet
        logger.info(
            f"\tlocate snippet: {i}/{confirmed_function_num}{confirmed_vul_function.function_name} patch num: {len(confirmed_vul_function.patches)}")
        succeed_locate_patches = []
        normalized_asm_codes_snippet_list = []
        for patch in confirmed_vul_function.patches:
            normalized_asm_codes_snippet = locate_snippet(locate_model,
                                                          confirmed_vul_function.get_function_name(),
                                                          patch,
                                                          confirmed_normalized_asm_codes)
            if normalized_asm_codes_snippet is not None:
                succeed_locate_patches.append(patch)
                normalized_asm_codes_snippet_list.append(normalized_asm_codes_snippet)
        logger.info(f"\tsucceed locate patch num: {len(normalized_asm_codes_snippet_list)}")

        # if can not locate, may be this is a false positive
        if not normalized_asm_codes_snippet_list:
            continue

        has_vul_function = True
        is_fixed = _judge_is_fixed(choice_model,
                                   confirmed_vul_function.get_function_name(),
                                   succeed_locate_patches,
                                   normalized_asm_codes_snippet_list)
        if not is_fixed:
            has_vul = True

        break

    if tc.has_vul():
        if has_vul:
            analysis.tp += 1  # TODO 这里当然有可能也是凑巧了，但是先不过多考虑。
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
    logger.success(f"\ttest summary: ")
    logger.success(
        f"\t\ttc:\thas_vul: {tc.has_vul()}, has_vul_function: {tc.has_vul_function()}, is_fixed: {tc.is_fixed()}")
    logger.success(f"\t\tresult:\thas_vul: {has_vul}, has_vul_function: {has_vul_function}, is_fixed: {is_fixed}")
    logger.success(f"\t\tconclusion: {tc_conclusion}")


def run_experiment():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    model_save_path = r"Resources/model_weights/model_1_weights.pth"

    logger.info(f"init model...")
    confirm_model = FunctionConfirmer(model_save_path=model_save_path, batch_size=128)
    model_2_save_path = r"Resources/model_weights/model_2_weights_back.pth"
    model_3_save_path = r"Resources/model_weights/model_3_weights.pth"
    locate_model = SnippetPositioner(model_save_path=model_2_save_path)
    choice_model = SnippetChoicer(model_save_path=model_3_save_path)
    # model = None
    logger.info(f"load test cases from {tc_save_path}")
    test_cases = load_test_cases(tc_save_path)
    logger.info(f"loaded {len(test_cases)} test cases")
    wrong_test_case_public_ids = {"CVE-2012-2774"}
    test_cases = [tc for tc in test_cases if tc.is_effective() and tc.public_id not in wrong_test_case_public_ids]
    logger.info(f"include {len(test_cases)} effective test cases")
    return
    test_cases = test_cases[:100]
    logger.info(f"Experiment tc num: {len(test_cases)}")

    asm_functions_cache = generate_asm_function_cache(test_cases)
    analysis = Analysis()
    for i, tc in enumerate(test_cases, 1):
        logger.info(f"confirm: {i} {tc.public_id}")
        run_tc(choice_model, confirm_model, locate_model, tc, analysis, asm_functions_cache)
    logger.info(f"test result:")
    logger.info(f"\ttotal: {analysis.total}")
    logger.info(f"\ttp: {analysis.tp}, fp: {analysis.fp}, tn: {analysis.tn}, fn: {analysis.fn}")
    logger.info(f"\tprecision: {analysis.precision}")
    logger.info(f"\trecall: {analysis.recall}")
    logger.info(f"\tf1: {analysis.f1}")
    logger.info(f"\taccuracy: {analysis.accuracy}")


if __name__ == '__main__':
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    run_experiment()

    """
    判定逻辑：
        1. 先用model 1 确认函数
        2. 再用model 2 确认代码片段，找到能定位的函数，以及片段
        3. 用model 3 判断是否修复
    
    model 1:
        目前 back 4 效果最好
        最新的，感觉还不如back 4， 可能也是训练的不够，现在才 98.9%的准确率 以及 0.035的loss，还可以继续训练。但是先训练model 3，训练一个出来，把整体流程都走通。
    """
