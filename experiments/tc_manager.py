from typing import List

from loguru import logger

from bintools.general.file_tool import load_from_json_file
from main.tc_models import VulConfirmTC

WRONG_TC_SET = {"CVE-2012-2774"}


def load_test_cases(tc_json_path) -> List[VulConfirmTC]:
    """
    加载测试用例
    """
    logger.info(f"load test cases from {tc_json_path}")
    test_cases = load_from_json_file(tc_json_path)

    test_cases = [VulConfirmTC.init_from_dict(tc) for tc in test_cases]
    logger.info(f"loaded {len(test_cases)} test cases")

    test_cases = [tc for tc in test_cases if tc.is_effective() and tc.public_id not in WRONG_TC_SET]
    logger.info(f"include {len(test_cases)} effective test cases")

    return test_cases


def split_test_cases(test_cases, batch_size=20) -> List[List[VulConfirmTC]]:
    start = 0
    batches = []
    while start < len(test_cases):
        test_cases_batch = test_cases[start:start + batch_size]
        batches.append(test_cases_batch)
        start += batch_size
    return batches
