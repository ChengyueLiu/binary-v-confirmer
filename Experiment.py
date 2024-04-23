import difflib
import multiprocessing
import re
from dataclasses import dataclass
from datetime import datetime
from multiprocessing import Pool
from typing import List
from bintools.general.normalize import normalize_asm_lines
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
        logger.info(vul_function.get_function_name(), src_param_count, asm_param_count)
        logger.info(data_item.src_codes)
        logger.info(data_item.asm_codes)
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
        for data_item in results:
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


def confirm_functions(model, tc: VulConfirmTC, asm_functions_cache: dict, prob_threshold=0.99):
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
    # return None, None
    # 3. 调用模型
    predictions = model.confirm(data_items)

    # 4. 确认结果
    logger.info(f"\tconfirmed functions:")
    confirmed_function_name = None
    confirmed_prob = 0
    confirmed_asm_codes = None
    asm_codes_list = []
    for data_item, (pred, prob) in zip(data_items, predictions):
        src_function_name = data_item.function_name
        if src_function_name.startswith("*"):
            src_function_name = src_function_name[1:]

        if pred == 1 and prob > prob_threshold:
            if prob > confirmed_prob:
                confirmed_function_name = data_item.function_name
                confirmed_prob = prob
                confirmed_asm_codes = data_item.asm_codes
            # 预览结果
            if src_function_name == data_item.bin_function_name:
                logger.info(f"\t**** {data_item.function_name} {data_item.bin_function_name} {prob} ****")
            else:
                logger.info(f'\t\t {data_item.function_name} {data_item.bin_function_name} {prob}')
            asm_codes_list.append(f"{data_item.bin_function_name}: {data_item.asm_codes}")
        else:
            if src_function_name == data_item.bin_function_name:
                logger.info(f"\txxxx {data_item.function_name} {data_item.bin_function_name} {prob} xxxx")
                asm_codes_list.append(f"{data_item.bin_function_name}: {data_item.asm_codes}")
    # logger.info(f"\tconfirmed asm codes:")
    # for asm_codes in asm_codes_list:
    #     logger.info(f"\t\t{asm_codes}")
    # 4. 预览ground truth
    logger.info(f"\tground truth: ")
    logger.info(f"\t\tvul: {tc.public_id}")
    logger.info(f"\t\tvul functions: {[func.function_name for func in tc.vul_functions]}")
    logger.info(f"\t\ttest_bin: {tc.test_bin.library_name} {tc.test_bin.version_tag} {tc.test_bin.binary_name}")
    logger.info(f"\t\tbin vul functions: {tc.ground_truth.contained_vul_function_names}")
    logger.info(f"\t\tis vul fixed: {tc.ground_truth.is_fixed}")
    logger.info(f"\tconfirm function: {confirmed_function_name} {confirmed_prob}")

    confirmed_vul_function = None
    for vul_function in tc.vul_functions:
        if vul_function.get_function_name() == confirmed_function_name:
            confirmed_vul_function = vul_function
            break

    return confirmed_vul_function, confirmed_asm_codes


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
                   asm_codes: List[str]) -> str:
    """
    片段定位
    """
    # 滑动窗口
    asm_codes_windows = split_list_by_sliding_window(asm_codes)
    # logger.info(f"asm codes length: {len(asm_codes)}, window num: {len(asm_codes_windows)}")

    # 分别定位开头和结尾
    # TODO 这里实际的源代码有点少，正规化处理后有可能不足3行。
    above_context = patch.vul_snippet_codes[:3]
    below_context = patch.vul_snippet_codes[-3:]
    start_data_items = []
    end_data_items = []
    for window in asm_codes_windows:
        start_data_item = DataItemForCodeSnippetPositioningModel(function_name=function_name,
                                                                 src_codes=above_context,
                                                                 asm_codes=window)
        start_data_item.normalize()
        start_data_items.append(start_data_item)

        end_data_item = DataItemForCodeSnippetPositioningModel(function_name=function_name,
                                                               src_codes=below_context,
                                                               asm_codes=window)
        end_data_item.normalize()
        end_data_items.append(end_data_item)

    # 处理结果
    all_predictions = locate_model.locate(start_data_items + end_data_items)
    mid_index = len(all_predictions) // 2  # 获取中间索引，用于分割开头和结尾的预测结果
    start_predictions = all_predictions[:mid_index]
    end_predictions = all_predictions[mid_index:]

    # 找到最大概率的片段
    start_asm_codes, start_asm_codes_prob = max(start_predictions, key=lambda x: x[1])
    logger.info(f"\tpatch location start: {start_asm_codes_prob} {start_asm_codes}")
    # if start_asm_codes_prob < 0.9:
    #     return None

    end_asm_codes, end_asm_codes_prob = max(end_predictions, key=lambda x: x[1])
    logger.info(f"\tpatch location end: {end_asm_codes_prob} {end_asm_codes}")

    # 找到对应的snippet
    normalized_asm_codes_str = " ".join(normalize_asm_lines(asm_codes))
    start_index = normalized_asm_codes_str.index(start_asm_codes)
    end_index = normalized_asm_codes_str.index(end_asm_codes)
    snippet = normalized_asm_codes_str[start_index:end_index]
    logger.info(f"\tasm length: {len(normalized_asm_codes_str)}, snippet length: {len(snippet)}, snippet: {snippet}")

    return snippet


def _judge_is_fixed(choice_model: SnippetChoicer,
                    function_name,
                    patches: List[VulFunctionPatch],
                    asm_codes_snippet_list: List[str]):
    # 生成模型输入
    data_items: List[DataItemForCodeSnippetConfirmModelMC] = []
    for patch, asm_codes_snippet in zip(patches, asm_codes_snippet_list):
        if asm_codes_snippet is None:
            continue
        data_item = DataItemForCodeSnippetConfirmModelMC(function_name=function_name,
                                                         asm_codes=asm_codes_snippet,
                                                         src_codes_0=patch.vul_snippet_codes,
                                                         src_codes_1=patch.fixed_snippet_codes)
        data_items.append(data_item)

    # 批量确认
    predictions = choice_model.choice(data_items)

    # 根据数量判断是否修复
    vul_count = 0
    fix_count = 0
    for pred, prob in predictions:
        if prob > 0.9:
            if pred == 0:
                vul_count += 1
            else:
                fix_count += 1
    if vul_count > fix_count:
        logger.info(f"\tvul count: {vul_count} fix count: {fix_count}")
        return True
    elif vul_count < fix_count:
        return False

    # 数量相同，认为无法判断 TODO 是否需要考虑概率？
    return None


def judge_is_fixed(locate_model: SnippetPositioner, choice_model: SnippetChoicer, vul_function: VulFunction,
                   asm_codes: List[str]):
    """
    判断函数是否被修复，任意一个片段被判定为修复，则认为函数被修复
    """

    # 每个patch 单独定位
    logger.info(f"\tpatch num: {len(vul_function.patches)}")
    asm_codes_snippet_list = []
    for patch in vul_function.patches:
        # 定位片段
        asm_codes_snippet = locate_snippet(locate_model, vul_function.get_function_name(), patch, asm_codes)

        asm_codes_snippet_list.append(asm_codes_snippet)

    logger.info(f"\tsucceed locate patch num: {len(asm_codes_snippet_list)}")
    result = _judge_is_fixed(choice_model, vul_function.get_function_name(), vul_function.patches,
                             asm_codes_snippet_list)
    return result


def run_tc(choice_model, confirm_model, locate_model, tc: VulConfirmTC, analysis, asm_functions_cache):
    has_vul = False
    has_vul_function = False
    is_fixed = False
    # locate vul function
    confirmed_vul_function, confirmed_asm_codes = confirm_functions(confirm_model, tc, asm_functions_cache)

    if confirmed_vul_function is not None:
        has_vul = True
        has_vul_function = True
        # judge is fixed
        is_fixed = judge_is_fixed(locate_model, choice_model, confirmed_vul_function, confirmed_asm_codes)
        if is_fixed:
            has_vul = False

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
    logger.success(f"\t\ttc:\thas_vul: {tc.has_vul()}, has_vul_function: {tc.has_vul_function()}, is_fixed: {tc.is_fixed()}")
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
    test_cases = test_cases[:3]
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
    run_experiment()

    """
    model 1:
        目前 back 4 效果最好，也不能叫最好，只能是凑巧最好。
        最新的，感觉还不如back 4， 可能也是训练的不够，现在才 98.9%的准确率 以及 0.035的loss，还可以继续训练。但是先训练model 3，训练一个出来，把整体流程都走通。
    """
