from collections import Counter

from Experiment import load_test_cases


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
    model_1_failed_indexes = []
    for tc_index, tc_result in tc_results.items():
        if tc_result["filter_flag"] == "True":
            if tc_result["model_1_flag"] == "False":
                print(tc_result["tc_index"], tc_result["tc_public_id"])
                model_1_failed_indexes.append(int(tc_result["tc_index"]))
        else:
            print(tc_result["tc_index"], tc_result["tc_public_id"])
            filter_failed_indexes.append(int(tc_result["tc_index"]))
    print(len(filter_failed_indexes), filter_failed_indexes)
    print(len(model_1_failed_indexes), model_1_failed_indexes)


if __name__ == '__main__':
    # analyze_tc()
    analyze_log("logs/tc_has_vul_349_0425.log")
