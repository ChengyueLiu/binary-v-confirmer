import multiprocessing
from collections import Counter
from typing import List

from loguru import logger
from tqdm import tqdm

from Experiment import load_test_cases
from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.dataset_and_data_provider import init_data_item_obj_from_dict


def analyze_tc():
    tc_save_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    test_cases = load_test_cases(tc_save_path)
    print(f"loaded {len(test_cases)} test cases")
    wrong_test_case_public_ids = {"CVE-2012-2774"}
    test_cases = [tc for tc in test_cases if tc.is_effective() and tc.public_id not in wrong_test_case_public_ids]
    print(f"include {len(test_cases)} effective test cases")

    test_cases = [tc for tc in test_cases if tc.has_vul()]
    print(f"experiment tc num: {len(test_cases)}")
    counter = Counter([tc.affected_library for tc in test_cases])
    for library, count in counter.items():
        print(f"{library}: {count}")


def analyze_log(path):
    with open(path, 'r') as f:
        lines = f.readlines()

    tc_results = {}
    for line in lines:
        if " - confirm tc: " in line:
            tc_index, tc_public_id = line.split(" - confirm tc: ")[1].split()
        elif " - confirm summary: " in line:
            filter_flag, model_1_flag, model_1_2_flag, model_1_2_precise_flag = line.split(" - confirm summary: ")[
                1].split()
            tc_results[tc_index] = {
                "tc_index": tc_index,
                "tc_public_id": tc_public_id,
                "filter_flag": filter_flag,
                "model_1_flag": model_1_flag,
                "model_1_2_flag": model_1_2_flag,
                "model_1_2_precise_flag": model_1_2_precise_flag
            }
        else:
            pass

    filter_failed_indexes = []
    for tc_index, tc_result in tc_results.items():
        if tc_result["filter_flag"] == "False":
            print(tc_result["tc_index"], tc_result["tc_public_id"])
            filter_failed_indexes.append(int(tc_result["tc_index"]))
    print(len(filter_failed_indexes), filter_failed_indexes)


def analyze_model_3_train_data_items():
    file_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/test_data_items_for_model_3.json"
    logger.info(f"读取文件：{file_path}")
    train_data_json = load_from_json_file(file_path)
    pool = multiprocessing.Pool(multiprocessing.cpu_count() - 4)
    data_items: List[DataItemForCodeSnippetConfirmModelMC] = list(
        tqdm(pool.imap_unordered(init_data_item_obj_from_dict, train_data_json), total=len(train_data_json),
             desc="多进程初始化训练对象"))
    pool.close()
    pool.join()
    count_0 = 0
    count_1 = 0
    for data_item in data_items[:10]:
        question = data_item.get_question_text()
        choice_0 = data_item.get_src_codes_0_text()[:300]
        choice_1 = data_item.get_src_codes_1_text()[:300]

        print(len(question + choice_0))
        print(len(question + choice_1))

    print(f"c0: {count_0}, c1: {count_1}")


if __name__ == '__main__':
    # analyze_tc()
    analyze_log("logs/tc_has_vul_349_0426.log")
    # analyze_model_3_train_data_items()
