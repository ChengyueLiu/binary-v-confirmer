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
from main.interface import DataItemForFunctionConfirmModel, DataItemForCodeSnippetPositioningModel
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
        print(vul_function.get_function_name(), src_param_count, asm_param_count)
        print(data_item.src_codes)
        print(data_item.asm_codes)
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


def check_result(tc, confirmed_function_name, analysis):
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
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def precision(self):
        return self.tp / (self.tp + self.fp) if self.tp + self.fp > 0 else 0

    @property
    def recall(self):
        return self.tp / (self.tp + self.fn) if self.tp + self.fn > 0 else 0

    @property
    def f1(self):
        return 2 * self.precision * self.recall / (
                self.precision + self.recall) if self.precision + self.recall > 0 else 0


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
        src_function_name = data_item.function_name
        if src_function_name.startswith("*"):
            src_function_name = src_function_name[1:]

        if pred == 1 and prob > prob_threshold:
            if prob > confirmed_prob:
                confirmed_function_name = data_item.bin_function_name
                confirmed_prob = prob

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
    logger.info(f"\tconfirmed asm codes:")
    for asm_codes in asm_codes_list:
        logger.info(f"\t\t{asm_codes}")
    logger.info(f"\tconfirm result: {confirmed_function_name} {confirmed_prob}")
    return confirmed_function_name, confirmed_prob


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


def locate_snippet(locate_model, function_name, patch: VulFunctionPatch, asm_codes: List[str]):
    """
    片段定位
    """
    # 滑动窗口
    asm_codes_windows = split_list_by_sliding_window(asm_codes)
    print(f"asm codes length: {len(asm_codes)}, window num: {len(asm_codes_windows)}")

    # 分别定位开头和结尾
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
    print(f"start: {start_asm_codes_prob} {start_asm_codes}")
    if start_asm_codes_prob < 0.9:
        return None

    end_asm_codes, end_asm_codes_prob = max(end_predictions, key=lambda x: x[1])
    print(f"end: {end_asm_codes_prob} {end_asm_codes}")

    # 找到对应的snippet
    normalized_asm_codes = " ".join(normalize_asm_lines(asm_codes))
    start_index = normalized_asm_codes.index(start_asm_codes)
    end_index = normalized_asm_codes.index(end_asm_codes)
    snippet = normalized_asm_codes[start_index:end_index]
    print(f"asm length: {len(normalized_asm_codes)}, snippet length: {len(snippet)}, snippet: {snippet}")

    return snippet


def choice_snippet(choice_model, function_name, patch: VulFunctionPatch, asm_codes_snippet: str):
    pass


def judge_is_fixed(locate_model, choice_model, vul_function: VulFunction, asm_codes: List[str]):
    """
    判断漏洞是否已修复
    """
    print(f"patch num: {len(vul_function.patches)}")
    for patch in vul_function.patches:
        # 定位片段
        asm_codes_snippet = locate_snippet(locate_model, vul_function.get_function_name(), patch, asm_codes)
        # 判断是否修复
        if asm_codes_snippet:
            pass


def run_experiment():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    model_save_path = r"Resources/model_weights/model_1_weights_back_4.pth"

    logger.info(f"init model...")
    model = FunctionConfirmer(model_save_path=model_save_path, batch_size=128)
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
    test_cases = test_cases[48:49]
    print(f"Experiment tc num: {len(test_cases)}")

    asm_functions_cache = generate_asm_function_cache(test_cases)
    analysis = Analysis()
    for i, tc in enumerate(test_cases, 1):
        logger.info(f"confirm: {i} {tc.public_id}")
        confirmed_function_name, confirmed_prob = confirm_functions(model, tc, asm_functions_cache)
        check_result(tc, confirmed_function_name, analysis)

    logger.info(f"test result:")
    logger.info(f"\ttc num: {len(test_cases)}")
    logger.info(f"test result:")
    logger.info(f"\ttp: {analysis.tp} fp: {analysis.fp} tn: {analysis.tn} fn: {analysis.fn}")
    logger.info(f"\tprecision: {analysis.precision}")
    logger.info(f"\trecall: {analysis.recall}")
    logger.info(f"\tf1: {analysis.f1}")


def debug_judge_is_fixed():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    tc_save_path = r"C:\Users\chengyue\Desktop\DATA\test_cases\bin_vul_confirm_tcs\final_vul_confirm_test_cases.json"
    model_save_path = r"Resources/model_weights/model_2_weights_back.pth"

    logger.info(f"load test cases from {tc_save_path}")
    test_cases = load_test_cases(tc_save_path)
    logger.info(f"loaded {len(test_cases)} test cases")
    test_cases = [tc for tc in test_cases if tc.is_effective()]
    logger.info(f"include {len(test_cases)} effective test cases")
    vul_function = test_cases[48].vul_functions[0]
    asm_codes = ['mov rax,fs:0x28', 'mov <MEM>,rax', 'xor eax,eax', 'mov rax,<MEM>', 'mov <MEM>,rax', 'mov rax,<MEM>',
                 'mov <MEM>,rax', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x1',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'lea rdx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,rdx', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rdx',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rdx', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rdx', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_ue_golomb_long>', 'mov <MEM>,eax', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,0x1', 'mov rdi,rax', 'call <field_end>', 'mov rax,<MEM>',
                 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'cmp <MEM>,rax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', 'sete al', 'movzx eax,al', 'mov rdx,<MEM>',
                 'mov rdx,<MEM>', 'mov rcx,rdx', 'mov edx,eax', 'mov esi,0x7fffffff', 'mov rdi,rcx',
                 'call <ff_thread_report_progress>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_ue_golomb_31>', 'mov <MEM>,eax', 'cmp <MEM>,0x9',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,<MEM>', 'mov rax,<MEM>', 'mov ecx,<MEM>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov r9d,esi', 'mov r8d,ecx', 'mov ecx,edx',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff',
                 '<JUMP> <LOC>', 'cmp <MEM>,0x4', '<JUMP> <LOC>', 'sub <MEM>,0x5', 'mov rax,<MEM>', 'mov <MEM>,0x1',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov eax,<MEM>', 'lea rdx,<MEM>', 'movzx eax,<MEM>',
                 'movzx eax,al', 'mov <MEM>,eax', 'cmp <MEM>,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>',
                 'mov <MEM>,0x1', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov eax,<MEM>', 'and eax,0x3',
                 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax', 'call <get_ue_golomb>',
                 'mov <MEM>,eax', 'cmp <MEM>,0xff', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'add rdx,0xa650',
                 'mov rax,<MEM>', 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'add rdx,0xa650',
                 'mov rdx,<MEM>', 'mov rax,<MEM>', 'add rax,0x4838', 'mov rsi,rdx', 'mov edx,0x5b', 'mov rdi,rax',
                 'mov rcx,rdx', 'rep movs es:<MEM>,ds:<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov edx,edx', 'add rdx,0xa630', 'mov rax,<MEM>', 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10',
                 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov edx,edx', 'add rdx,0xa630', 'mov rdx,<MEM>', 'mov rax,<MEM>',
                 'add rax,0x438c', 'mov ecx,0x4ac', 'mov rsi,<MEM>', 'mov <MEM>,rsi', 'mov esi,ecx', 'add rsi,rax',
                 'lea rdi,<MEM>', 'mov esi,ecx', 'add rsi,rdx', 'add rsi,0x8', 'mov rsi,<MEM>', 'mov <MEM>,rsi',
                 'lea rdi,<MEM>', 'and rdi,0xfffffffffffffff8', 'sub rax,rdi', 'sub rdx,rax', 'add ecx,eax',
                 'and ecx,0xfffffff8', 'mov eax,ecx', 'shr eax,0x3', 'mov eax,eax', 'mov rsi,rdx', 'mov rcx,rax',
                 'rep movs es:<MEM>,ds:<MEM>', 'mov rax,<MEM>', 'add rax,0x438c', 'mov rdx,<MEM>', 'mov rbx,<MEM>',
                 'mov rdi,rax', 'call <ff_h264_get_profile>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>',
                 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'shl eax,0x4', 'mov edx,eax', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'mov ecx,0x2', 'sub ecx,eax', 'mov eax,ecx', 'imul eax,edx', 'shl eax,0x4',
                 'mov edx,eax', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov rsi,rdx', 'mov rdi,rax', 'call <av_cmp_q>', 'test eax,eax', '<JUMP> <LOC>', 'mov eax,0x1',
                 '<JUMP> <LOC>', 'mov eax,0x0', 'mov <MEM>,eax', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'cmp rax,<MEM>', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x1',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,0x0', 'lea rsi,<MEM>',
                 'mov rdi,rax', 'call <av_log_missing_feature>', 'mov eax,0xbaa8beb0', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'mov ecx,0x2', 'sub ecx,eax', 'mov eax,ecx', 'imul edx,eax', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', 'setle al', 'movzx edx,al', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'shl eax,0x4', 'mov edx,eax', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'shl eax,0x4', 'mov edx,eax', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,0x0', 'mov rdi,rax',
                 'call <free_tables>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdi,rax', 'call <flush_dpb>',
                 'mov rax,<MEM>', 'mov rdi,rax', 'call <ff_mpv_common_end>', 'mov rax,<MEM>', 'mov <MEM>,0x0',
                 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'cmp rax,<MEM>', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>',
                 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'add eax,0xf', 'and eax,0xfffffff0', 'mov edx,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov ecx,0x2', 'sub ecx,eax', 'mov eax,ecx',
                 'shl eax,0x4', 'add eax,edx', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov ecx,0x2',
                 'sub ecx,eax', 'mov eax,0x0', 'sub eax,ecx', 'shl eax,0x4', 'and edx,eax', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>',
                 'mov esi,0x30', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>',
                 'mov edx,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov ecx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov esi,ecx', 'mov rdi,rax',
                 'call <avcodec_set_dimensions>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov esi,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov ecx,0x1', '<JUMP> <LOC>',
                 'mov ecx,0x2', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov eax,0xf', '<JUMP> <LOC>', 'mov eax,0x7', 'cmp eax,edx', 'cmova eax,edx',
                 'imul eax,ecx', 'sub esi,eax', 'mov edx,esi', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov esi,eax', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov edi,0x10', 'mov ecx,edx', 'sar edi,cl', 'mov edx,edi',
                 'sub edx,0x1', 'cmp eax,edx', 'cmovbe edx,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov ecx,eax',
                 'shl edx,cl', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov ecx,0x2', 'sub ecx,eax', 'mov eax,ecx',
                 'imul eax,edx', 'sub esi,eax', 'mov edx,esi', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov rdx,<MEM>', 'mov <MEM>,rdx', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov r9d,0x9bf', 'lea r8,<MEM>',
                 'lea rcx,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x8', 'mov edi,0x0', 'mov eax,0x0', 'call <av_log>',
                 'call <abort@plt>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x80',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x8', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x7', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0xe', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0xb', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0xd', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x9', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x8', 'setg al', 'movzx edx,al', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rcx,<MEM>', 'add rcx,0x3c68',
                 'mov esi,eax', 'mov rdi,rcx', 'call <ff_h264dsp_init>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rcx,<MEM>', 'mov ecx,<MEM>', 'mov esi,ecx', 'mov rcx,<MEM>',
                 'lea rdi,<MEM>', 'mov ecx,edx', 'mov edx,eax', 'call <ff_h264_pred_init>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x8', '<JUMP> <LOC>', 'mov edx,0x20', '<JUMP> <LOC>', 'mov edx,0x10',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'add rdx,0x1888',
                 'mov rsi,rax', 'mov rdi,rdx', 'call <ff_dsputil_init>', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov ecx,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov r8d,ecx',
                 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov edx,0x2', '<JUMP> <LOC>',
                 'mov edx,0x1', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov eax,eax',
                 'mov <MEM>,rax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2b', '<JUMP> <LOC>', 'shl <MEM>,1',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov edx,eax', 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rsi,<MEM>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdi,<MEM>', 'mov rax,<MEM>', 'mov r8d,0x40000000',
                 'mov rcx,rax', 'call <av_reduce>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'sub eax,0x8', 'cmp eax,0x6',
                 '<JUMP> <LOC>', 'mov eax,eax', 'lea rdx,<MEM>', 'lea rax,<MEM>', 'mov eax,<MEM>', 'cdqe',
                 'lea rdx,<MEM>', 'add rax,rdx', 'notrack jmp rax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x54', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,0x4c', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x50', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,0x46', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,0x56', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x4e',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,0x4a', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x48',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,0x13a', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x136', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,0x132', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x12e', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x13c',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x138', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x134',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x130', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x2', '<JUMP> <LOC>', 'mov edx,0xe', '<JUMP> <LOC>', 'mov edx,0x5', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,0x52', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x30', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x8', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x18', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov edx,0xd', '<JUMP> <LOC>',
                 'mov edx,0x4', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov rcx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>',
                 'lea rax,<MEM>', '<JUMP> <LOC>', 'lea rax,<MEM>', 'mov rdx,<MEM>', 'mov rdx,<MEM>', 'mov rsi,<MEM>',
                 'mov rbx,<MEM>', 'mov rsi,rax', 'mov rdi,rdx', 'call rcx', 'mov <MEM>,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov ecx,edx', 'lea rdx,<MEM>',
                 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xbebbb1b7', '<JUMP> <LOC>',
                 'nop', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov esi,edx', 'mov edi,eax',
                 'call <ff_find_hwaccel>', 'mov <MEM>,rax', 'mov rax,<MEM>', 'mov rdi,rax', 'call <ff_mpv_common_init>',
                 'test eax,eax', 'jns 38900d <decode_slice_header+OFFSET>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov <MEM>,0x1', 'mov rax,<MEM>',
                 'mov rdi,rax', 'call <init_scan_tables>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_h264_alloc_tables>', 'test eax,eax', 'jns 38907f <decode_slice_header+OFFSET>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0',
                 'call <av_log>', 'mov eax,0xfffffff4', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'and eax,0x2', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <context_init>', 'test eax,eax', 'jns 3894c3 <decode_slice_header+OFFSET>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov <MEM>,0x1', '<JUMP> <LOC>', 'mov edi,0x66ee0',
                 'call <av_malloc>', 'mov rcx,rax', 'mov rax,<MEM>', 'mov edx,<MEM>', 'add rdx,0xcd9c', 'mov <MEM>,rcx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'add rdx,0xcd9c', 'mov rax,<MEM>', 'mov <MEM>,rax', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'add rdx,0x6c', 'mov rcx,<MEM>', 'mov rax,<MEM>', 'mov edx,0x3c68', 'mov rsi,rcx',
                 'mov rdi,rax', 'call <memcpy@plt>', 'mov rax,<MEM>', 'add rax,0x3c68', 'mov edx,0x63278',
                 'mov esi,0x0', 'mov rdi,rax', 'call <memset@plt>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov rcx,<MEM>',
                 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx',
                 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>',
                 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx',
                 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>',
                 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx',
                 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>',
                 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx',
                 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>',
                 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx',
                 'mov <MEM>,rbx', 'mov rcx,<MEM>', 'mov rbx,<MEM>', 'mov <MEM>,rcx', 'mov <MEM>,rbx', 'mov rdx,<MEM>',
                 'mov <MEM>,rdx', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'add rax,0x438c', 'add rdx,0x438c', 'mov ecx,0x4ac',
                 'mov rsi,<MEM>', 'mov <MEM>,rsi', 'mov esi,ecx', 'add rsi,rax', 'lea rdi,<MEM>', 'mov esi,ecx',
                 'add rsi,rdx', 'add rsi,0x8', 'mov rsi,<MEM>', 'mov <MEM>,rsi', 'lea rdi,<MEM>',
                 'and rdi,0xfffffffffffffff8', 'sub rax,rdi', 'sub rdx,rax', 'add ecx,eax', 'and ecx,0xfffffff8',
                 'mov eax,ecx', 'shr eax,0x3', 'mov eax,eax', 'mov rsi,rdx', 'mov rcx,rax',
                 'rep movs es:<MEM>,ds:<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'add rax,0x4838', 'add rdx,0x4838',
                 'mov ecx,0x5b', 'mov rdi,rax', 'mov rsi,rdx', 'rep movs es:<MEM>,ds:<MEM>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rdi,rax', 'call <init_scan_tables>', 'mov edx,<MEM>',
                 'mov rcx,<MEM>', 'mov rax,<MEM>', 'mov rsi,rcx', 'mov rdi,rax', 'call <clone_tables>', 'add <MEM>,0x1',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov <MEM>,0x0', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'add rdx,0xcd9c', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <context_init>', 'test eax,eax', 'jns 3894a7 <decode_slice_header+OFFSET>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov eax,0xffffffff', '<JUMP> <LOC>', 'add <MEM>,0x1', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'cmp rax,<MEM>', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov rdi,rax', 'call <init_dequant_tables>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'mov rdx,<MEM>', 'add rdx,0x3a88', 'mov esi,eax', 'mov rdi,rdx', 'call <get_bits>', 'mov edx,eax',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov <MEM>,0x0',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', 'sete al', 'movzx edx,al', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov <MEM>,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'cmp <MEM>,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10',
                 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_bits1>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_bits1>', 'add eax,0x1', 'mov edx,eax', 'mov rax,<MEM>',
                 'mov <MEM>,edx', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x3', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', 'setne al',
                 'movzx edx,al', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov ecx,<MEM>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov r8d,ecx', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10',
                 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov eax,0xbebbb1b7', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', 'js 389854 <decode_slice_header+OFFSET>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov edx,0x1',
                 'mov ecx,eax', 'shl edx,cl', 'mov eax,edx', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov eax,<MEM>', 'sub <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'sub eax,<MEM>', 'mov edx,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'sub edx,eax', 'mov eax,edx',
                 'sub eax,0x1', 'mov <MEM>,eax', 'cmp <MEM>,0x0', 'jns 389841 <decode_slice_header+OFFSET>',
                 'mov eax,<MEM>', 'add <MEM>,eax', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'cmp <MEM>,rax', '<JUMP> <LOC>', 'cmp <MEM>,0x2', 'sete al',
                 'movzx eax,al', 'mov rdx,<MEM>', 'mov rdx,<MEM>', 'mov rcx,rdx', 'mov edx,eax', 'mov esi,0x7fffffff',
                 'mov rdi,rcx', 'call <ff_thread_report_progress>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'cmp <MEM>,0x0',
                 '<JUMP> <LOC>', 'cmp <MEM>,0x3', '<JUMP> <LOC>', 'cmp <MEM>,0x1', 'sete al', 'movzx eax,al',
                 'mov rdx,<MEM>', 'mov rdx,<MEM>', 'mov rcx,rdx', 'mov edx,eax', 'mov esi,0x7fffffff', 'mov rdi,rcx',
                 'call <ff_thread_report_progress>', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'cmp <MEM>,0x0', '<JUMP> <LOC>',
                 'cmp <MEM>,0x3', '<JUMP> <LOC>', 'cmp <MEM>,0x1', 'sete al', 'movzx eax,al', 'mov rdx,<MEM>',
                 'mov rdx,<MEM>', 'mov rcx,rdx', 'mov edx,eax', 'mov esi,0x7fffffff', 'mov rdi,rcx',
                 'call <ff_thread_report_progress>', '<JUMP> <LOC>', 'cmp <MEM>,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'cmp <MEM>,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov ecx,<MEM>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov r8d,ecx', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10',
                 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov eax,0xbebbb1b7', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov esi,0x0', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log_ask_for_sample>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx',
                 'mov eax,0xbebbb1b7', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>',
                 'mov <MEM>,rdx', '<JUMP> <LOC>', 'nop', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', '<JUMP> <LOC>', 'mov eax,0x0',
                 'mov <MEM>,rax', 'mov rax,<MEM>', 'mov ecx,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov r8d,ecx', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x30', 'mov rdi,rax',
                 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>', 'mov rdi,rax', 'call <ff_h264_frame_start>',
                 'test eax,eax', 'jns 389b81 <decode_slice_header+OFFSET>', 'mov eax,0xffffffff', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov esi,0x1', 'mov ecx,edx', 'shl esi,cl',
                 'mov ecx,esi', 'cdq', 'idiv ecx', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,0x0',
                 'mov esi,0x7fffffff', 'mov rdi,rax', 'call <ff_thread_report_progress>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov edx,0x1', 'mov esi,0x7fffffff', 'mov rdi,rax',
                 'call <ff_thread_report_progress>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_generate_sliding_window_mmcos>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'lea rcx,<MEM>', 'mov rax,<MEM>', 'mov rsi,rcx', 'mov rdi,rax',
                 'call <ff_h264_execute_ref_pic_marking>', 'test eax,eax', 'jns 389c96 <decode_slice_header+OFFSET>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x8', 'test eax,eax', '<JUMP> <LOC>',
                 'mov eax,0xbebbb1b7', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'shl eax,0x4', 'mov edi,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'shl eax,0x4', 'mov r9d,eax', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov r8d,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'mov rcx,<MEM>', 'mov rcx,<MEM>',
                 'lea rsi,<MEM>', 'mov rcx,<MEM>', 'mov rcx,<MEM>', 'mov r10,rcx', 'sub rsp,0x8', 'push rdi',
                 'mov rcx,rdx', 'mov rdx,rax', 'mov rdi,r10', 'call <av_image_copy>', 'add rsp,0x10', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'add edx,0x2', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov rdx,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', 'js 389df1 <decode_slice_header+OFFSET>', 'mov rax,<MEM>', 'mov esi,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov edi,0x1',
                 'mov ecx,eax', 'shl edi,cl', 'mov ecx,edi', 'mov eax,edx', 'cdq', 'idiv ecx', 'mov eax,edx',
                 'cmp esi,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x3', 'setne al', 'movzx edx,al', 'mov rax,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', 'sete al', 'movzx edx,al',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov esi,0x7fffffff', 'mov rdi,rax',
                 'call <ff_thread_report_progress>', 'mov rax,<MEM>', 'mov <MEM>,0x1', 'mov rax,<MEM>', 'mov <MEM>,0x0',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x3', 'setne al', 'movzx edx,al', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rdi,rax', 'call <ff_h264_frame_start>', 'test eax,eax',
                 'jns 389f7d <decode_slice_header+OFFSET>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov eax,0xffffffff',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,0x0', 'mov rdi,rax', 'call <ff_release_unused_pictures>',
                 'mov rax,<MEM>', 'cmp rax,<MEM>', '<JUMP> <LOC>', 'mov rdx,<MEM>', 'mov rax,<MEM>', 'mov rsi,rdx',
                 'mov rdi,rax', 'call <clone_slice>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>',
                 'mov edx,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov edx,0x1', '<JUMP> <LOC>',
                 'mov edx,0x0', 'mov eax,<MEM>', 'mov ecx,edx', 'shl eax,cl', 'mov edx,eax', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax',
                 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'mov ecx,eax', 'mov eax,<MEM>', 'mov edx,0x0', 'div ecx', 'mov eax,edx', 'mov edx,eax',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov ebx,eax', 'mov eax,<MEM>', 'mov edx,0x0', 'div ebx',
                 'mov edx,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov eax,0x1', '<JUMP> <LOC>', 'mov eax,0x0',
                 'mov ecx,eax', 'shl edx,cl', 'mov eax,edx', 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov edx,0x1', 'mov ecx,eax', 'shl edx,cl',
                 'mov rax,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'add eax,eax',
                 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'add eax,0x1',
                 'mov edx,0x1', 'mov ecx,eax', 'shl edx,cl', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x5', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_ue_golomb>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rdx,<MEM>', 'add rdx,0x3a88', 'mov esi,eax', 'mov rdi,rdx',
                 'call <get_bits>', 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax', 'call <get_se_golomb>', 'mov rdx,<MEM>',
                 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_se_golomb>', 'mov rdx,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax', 'call <get_se_golomb>', 'mov rdx,<MEM>',
                 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov rdi,rax', 'call <init_poc>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_ue_golomb>', 'mov rdx,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x3', '<JUMP> <LOC>', 'mov eax,0xf', '<JUMP> <LOC>', 'mov eax,0x1f', 'mov <MEM>,eax',
                 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax', 'call <get_bits1>', 'mov edx,eax', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax', 'call <get_bits1>', 'mov <MEM>,eax',
                 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_ue_golomb>', 'add eax,0x1', 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88',
                 'mov rdi,rax', 'call <get_ue_golomb>', 'add eax,0x1', 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x1', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>',
                 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>',
                 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>', 'mov ecx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'lea edi,<MEM>', 'mov esi,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'sub rsp,0x8', 'push rcx', 'mov r9d,edi', 'mov r8d,esi', 'mov ecx,edx',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'add rsp,0x10',
                 'mov rax,<MEM>', 'mov <MEM>,0x1', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov eax,0xbebbb1b7', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov <MEM>,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x1', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'cmp <MEM>,0x0', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rdi,rax', 'call <ff_h264_fill_default_ref_list>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_h264_decode_ref_pic_list_reordering>', 'test eax,eax',
                 'jns 38a660 <decode_slice_header+OFFSET>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov eax,0xffffffff', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'lea rdx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,rdx', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'add rdx,0x470',
                 'mov rsi,rax', 'mov rdi,rdx', 'call <ff_copy_picture>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rdx',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rdx,<MEM>', 'add rdx,0x920', 'mov rsi,rax', 'mov rdi,rdx',
                 'call <ff_copy_picture>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rdi,rax', 'call <pred_weight_table>', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,0xffffffff', 'mov rdi,rax', 'call <implicit_weight_table>',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov <MEM>,0x0', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'add rdx,0x19b84', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'add rdx,0x19b84', 'mov <MEM>,0x0', 'add <MEM>,0x1', 'cmp <MEM>,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov rax,<MEM>',
                 'mov rsi,rdx', 'mov rdi,rax', 'call <ff_h264_decode_ref_pic_marking>', 'test eax,eax',
                 'jns 38a85a <decode_slice_header+OFFSET>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'and eax,0x8', 'test eax,eax', '<JUMP> <LOC>', 'mov eax,0xbebbb1b7', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_h264_fill_mbaff_ref_list>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov esi,0x0',
                 'mov rdi,rax', 'call <implicit_weight_table>', 'mov rax,<MEM>', 'mov esi,0x1', 'mov rdi,rax',
                 'call <implicit_weight_table>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_h264_direct_dist_scale_factor>', 'mov rax,<MEM>', 'mov rdi,rax',
                 'call <ff_h264_direct_ref_list_init>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88',
                 'mov rdi,rax', 'call <get_ue_golomb_31>', 'mov <MEM>,eax', 'cmp <MEM>,0x2', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0',
                 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>', 'mov ebx,<MEM>', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_se_golomb>', 'add eax,ebx', 'mov <MEM>,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov eax,edx', 'add eax,eax', 'add eax,edx',
                 'add eax,eax', 'add eax,0x33', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0',
                 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rdx,<MEM>', 'mov <MEM>,rdx', 'mov <MEM>,0x0',
                 'mov <MEM>,eax', 'mov rsi,<MEM>', 'mov eax,<MEM>', 'movsxd rcx,eax', 'mov eax,<MEM>', 'movsxd rdx,eax',
                 'mov rax,rdx', 'shl rax,0x2', 'add rax,rdx', 'add rax,rax', 'add rax,rdx', 'shl rax,0x3',
                 'add rax,rsi', 'add rax,rcx', 'add rax,0x4a5c', 'movzx eax,<MEM>', 'movzx edx,al', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov rdx,<MEM>', 'mov <MEM>,rdx', 'mov <MEM>,0x1',
                 'mov <MEM>,eax', 'mov rsi,<MEM>', 'mov eax,<MEM>', 'movsxd rcx,eax', 'mov eax,<MEM>', 'movsxd rdx,eax',
                 'mov rax,rdx', 'shl rax,0x2', 'add rax,rdx', 'add rax,rax', 'add rax,rdx', 'shl rax,0x3',
                 'add rax,rsi', 'add rax,rcx', 'add rax,0x4a5c', 'movzx eax,<MEM>', 'movzx edx,al', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x6', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_bits1>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x6',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x5', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'add rax,0x3a88', 'mov rdi,rax', 'call <get_se_golomb>', 'mov rax,<MEM>', 'mov <MEM>,0x1',
                 'mov rax,<MEM>', 'mov <MEM>,0x34', 'mov rax,<MEM>', 'mov <MEM>,0x34', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_ue_golomb_31>', 'mov <MEM>,eax', 'cmp <MEM>,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax',
                 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff', '<JUMP> <LOC>', 'mov edx,<MEM>', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'xor eax,0x1', 'mov edx,eax', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_se_golomb>', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'add edx,eax',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'add rax,0x3a88', 'mov rdi,rax',
                 'call <get_se_golomb>', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'add edx,eax',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x68', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x68', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov ecx,<MEM>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov r8d,ecx', 'mov ecx,edx',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0xffffffff',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x2f', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1f', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0xf', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x7', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x0', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x1', 'test eax,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x2', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov <MEM>,0x1',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x20', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov rax,<MEM>',
                 'mov <MEM>,0x1', 'mov rax,<MEM>', 'cmp rax,<MEM>', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'lea rdx,<MEM>', 'mov esi,0x10', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov eax,0x1',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax',
                 'cmovle eax,edx', 'mov edx,0x43', 'mov ecx,edx', 'sub ecx,eax', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov esi,0x0', 'test eax,eax', 'cmovs eax,esi', 'cmp edx,eax',
                 'cmovge eax,edx', 'sub ecx,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>', 'mov eax,edx',
                 'add eax,eax', 'add eax,edx', 'add eax,eax', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'lea edx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,edx',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'sub eax,0x1', 'and eax,0xf', 'mov ecx,eax', 'mov esi,edx',
                 'mov rax,<MEM>', 'movsxd rdx,ecx', 'add rdx,0x33750', 'mov <MEM>,si', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'and eax,0xf', 'mov edx,eax', 'mov rax,<MEM>', 'movsxd rdx,edx', 'add rdx,0x33750', 'movzx eax,<MEM>',
                 'cwde', 'lea edx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0xf', 'mov edx,eax', 'mov rax,<MEM>', 'movsxd rdx,edx',
                 'add rdx,0x33750', 'movzx eax,<MEM>', 'movsx edx,ax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp edx,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0xf', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov edx,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov r8d,0x10', 'mov ecx,edx', 'lea rdx,<MEM>',
                 'mov esi,0x18', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>', 'mov <MEM>,0x0', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0xf', 'mov edx,eax', 'mov eax,<MEM>', 'movsxd rdx,edx',
                 'add rdx,rdx', 'add rax,rdx', 'shl rax,0x8', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'add rax,rdx',
                 'mov <MEM>,rax', 'mov <MEM>,0x0', '<JUMP> <LOC>', 'mov eax,<MEM>', 'mov <MEM>,0x3c', 'mov rax,<MEM>',
                 'mov ecx,<MEM>', 'mov edx,<MEM>', 'imul rcx,rcx,0x4b0', 'imul rdx,rdx,0xe100', 'add rdx,rcx',
                 'add rax,rdx', 'add rax,0x33690', 'mov rax,<MEM>', 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov ecx,<MEM>', 'mov edx,<MEM>', 'imul rcx,rcx,0x4b0', 'imul rdx,rdx,0xe100', 'add rdx,rcx',
                 'add rax,rdx', 'add rax,0x33710', 'mov rax,<MEM>', 'mov <MEM>,rax', 'mov <MEM>,0x0', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov edx,<MEM>', 'movsxd rdx,edx', 'add rdx,0xa75a', 'mov rax,<MEM>', 'mov rax,<MEM>',
                 'cmp <MEM>,rax', '<JUMP> <LOC>', 'mov eax,<MEM>', 'mov edx,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>',
                 'add <MEM>,0x1', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'mov <MEM>,0x0',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'movsxd rdx,edx', 'add rdx,0xa77a', 'mov rax,<MEM>',
                 'test rax,rax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>', 'movsxd rdx,edx', 'add rdx,0xa77a',
                 'mov rax,<MEM>', 'mov rax,<MEM>', 'cmp <MEM>,rax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov edx,<MEM>',
                 'mov eax,<MEM>', 'add edx,eax', 'mov eax,<MEM>', 'mov <MEM>,edx', '<JUMP> <LOC>', 'add <MEM>,0x1',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp <MEM>,eax', '<JUMP> <LOC>', 'add <MEM>,0x1', 'cmp <MEM>,0xf',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'add rax,0x4', 'mov <MEM>,0xffffffff', 'mov edx,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,edx', 'mov <MEM>,0x0', '<JUMP> <LOC>', 'mov eax,<MEM>', 'mov eax,<MEM>',
                 'lea esi,<MEM>', 'mov rax,<MEM>', 'mov ecx,<MEM>', 'mov edx,<MEM>', 'imul rcx,rcx,0x4b0',
                 'imul rdx,rdx,0xe100', 'add rdx,rcx', 'add rax,rdx', 'add rax,0x3377c', 'mov eax,<MEM>', 'and eax,0x3',
                 'mov edx,eax', 'mov eax,<MEM>', 'add eax,0x2', 'mov eax,eax', 'lea rcx,<MEM>', 'mov rax,<MEM>',
                 'add rax,rcx', 'add edx,esi', 'mov <MEM>,edx', 'add <MEM>,0x1', 'cmp <MEM>,0xf', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'add rax,0x4c', 'mov <MEM>,0xffffffff', 'mov rdx,<MEM>', 'add rdx,0x48',
                 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov <MEM>,0x10', '<JUMP> <LOC>', 'mov eax,<MEM>', 'sub eax,0x10',
                 'shr eax,1', 'mov eax,eax', 'mov eax,<MEM>', 'lea esi,<MEM>', 'mov rax,<MEM>', 'mov ecx,<MEM>',
                 'mov edx,<MEM>', 'imul rcx,rcx,0x4b0', 'imul rdx,rdx,0xe100', 'add rdx,rcx', 'add rax,rdx',
                 'add rax,0x3377c', 'mov eax,<MEM>', 'and eax,0x3', 'mov edx,eax', 'mov eax,<MEM>', 'add eax,0x4',
                 'mov eax,eax', 'lea rcx,<MEM>', 'mov rax,<MEM>', 'add rax,rcx', 'add edx,esi', 'mov <MEM>,edx',
                 'add <MEM>,0x1', 'cmp <MEM>,0x2f', '<JUMP> <LOC>', 'add <MEM>,0x1', 'cmp <MEM>,0x1', '<JUMP> <LOC>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x4000', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'test eax,eax', '<JUMP> <LOC>', 'mov edx,0x0', '<JUMP> <LOC>', 'mov edx,0x10', 'mov rax,<MEM>',
                 'mov <MEM>,edx', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', '<JUMP> <LOC>',
                 'mov eax,0x0', 'mov rdx,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'and eax,0x1', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x3',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>', 'lea rbx,<MEM>',
                 '<JUMP> <LOC>', 'lea rbx,<MEM>', '<JUMP> <LOC>', 'lea rbx,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x1', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax', '<JUMP> <LOC>',
                 'lea r12,<MEM>', '<JUMP> <LOC>', 'lea r12,<MEM>', 'mov rax,<MEM>', 'mov r15d,<MEM>', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'mov edx,eax', 'shr edx,0x1f', 'add eax,edx', 'sar eax,1', 'sub eax,0x1a',
                 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov edx,eax', 'shr edx,0x1f', 'add eax,edx',
                 'sar eax,1', 'sub eax,0x1a', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>',
                 'mov eax,<MEM>', 'mov <MEM>,eax', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x5', '<JUMP> <LOC>',
                 'lea r14,<MEM>', '<JUMP> <LOC>', 'lea r14,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'test eax,eax',
                 '<JUMP> <LOC>', 'lea r13,<MEM>', '<JUMP> <LOC>', 'lea r13,<MEM>', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'mov edi,eax', 'call <av_get_picture_type_char>', 'movsx r8d,al', 'mov rax,<MEM>', 'mov eax,<MEM>',
                 'cmp eax,0x3', '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov eax,<MEM>', 'cmp eax,0x1', '<JUMP> <LOC>',
                 'lea rdx,<MEM>', '<JUMP> <LOC>', 'lea rdx,<MEM>', '<JUMP> <LOC>', 'lea rdx,<MEM>', 'mov rax,<MEM>',
                 'mov esi,<MEM>', 'mov rax,<MEM>', 'mov rdi,<MEM>', 'mov ecx,<MEM>', 'push rbx', 'push r12', 'push r15',
                 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>',
                 'push rax', 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax',
                 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax', 'mov eax,<MEM>', 'push rax', 'push r14',
                 'push r13', 'push r8', 'mov r9d,ecx', 'mov r8,rdx', 'mov ecx,esi', 'lea rdx,<MEM>', 'mov esi,0x30',
                 'mov eax,0x0', 'call <av_log>', 'sub rsp,0xffffffffffffff80', 'mov eax,0x0', 'mov rbx,<MEM>',
                 'xor rbx,fs:0x28', '<JUMP> <LOC>', 'call <__stack_chk_fail@plt>', 'lea rsp,<MEM>', 'pop rbx',
                 'pop r12', 'pop r13', 'pop r14', 'pop r15', 'pop rbp', 'ret']

    logger.info(f"init model...")
    locate_model = SnippetPositioner(model_save_path=model_save_path)
    choice_model = None
    judge_is_fixed(locate_model, choice_model, vul_function, asm_codes)


if __name__ == '__main__':
    # run_experiment()
    debug_judge_is_fixed()
