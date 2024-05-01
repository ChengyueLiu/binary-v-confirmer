import os
import sys
from datetime import datetime
from typing import List

from loguru import logger

from experiments import tc_manager
from experiments.extractor_runner import generate_asm_function_cache
from experiments.tc_manager import split_test_cases
from experiments.tc_runner import TCRunner
from main.tc_models import VulConfirmTC

# 获取当前时间并格式化为字符串，例如 '20230418_101530'
start_time = datetime.now().strftime("%Y%m%d_%H%M%S")
logger.remove()
logger.add(sys.stdout, level="INFO")
# 添加日志处理器，文件名包含脚本开始时间
logger.add(f"logs/experiment_{start_time}.log", level="INFO")


def run_experiment():
    # load test_cases
    tc_json_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    test_cases: List[VulConfirmTC] = tc_manager.load_test_cases(tc_json_path)

    # tc runner
    function_confirm_model_pth = r"Resources/model_weights/model_1_weights_back_4.pth"
    snippet_position_model_pth = r"Resources/model_weights/model_2_weights_back.pth"
    snippet_choice_model_pth = r"Resources/model_weights/model_3_weights.pth"
    tc_runner = TCRunner(function_confirm_model_pth, snippet_position_model_pth, snippet_choice_model_pth)

    # experiment test cases
    test_cases: List[VulConfirmTC] = [tc for tc in test_cases
                                      if tc.has_vul()][230:240]
    logger.info(f"Experiment tc num: {len(test_cases)}")

    # run test cases
    batch_size = 20
    test_cases_batches: List[List[VulConfirmTC]] = split_test_cases(test_cases, batch_size)

    tc_count = 0
    for batch_i, test_cases_batch in enumerate(test_cases_batches, 0):
        start = batch_size * batch_i + 1
        tc_count += len(test_cases_batch)

        # generate asm cache
        asm_functions_cache = generate_asm_function_cache(test_cases_batch)

        # run test cases
        for i, tc in enumerate(test_cases_batch, start):
            logger.info(f"run tc: {i} {tc.public_id} {tc.affected_library}")
            tc_runner.run(tc, asm_functions_cache)

        # analysis result
        tc_runner.analysis.print_analysis_result(tc_count)

    logger.success(f"all done.")


if __name__ == '__main__':
    os.environ['TOKENIZERS_PARALLELISM'] = 'false'
    run_experiment()

    """
    目标：Less False Positive
    
    2. 
    """
