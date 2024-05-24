from typing import List

from experiments import tc_manager
from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file
from main.tc_models import VulConfirmTC


def generate_params():
    tc_json_path = "/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/final_vul_confirm_test_cases.json"
    test_cases: List[VulConfirmTC] = tc_manager.load_test_cases(tc_json_path)
    test_cases: List[VulConfirmTC] = [tc for tc in test_cases if tc.has_vul_function()]

    cache_dict = {}
    new_test_cases = []
    for i, tc in enumerate(test_cases, 1):
        try:
            print(f"process tc: {i}/{len(test_cases)} {tc.public_id}")
            binary_path = tc.test_bin.binary_path
            if binary_path in cache_dict:
                asm_function_dict = cache_dict[binary_path]
            else:
                asm_function_dict = parse_objdump_file(binary_path, ignore_warnings=True)
                cache_dict[binary_path] = asm_function_dict
            for vul_function in tc.vul_functions:
                function_name = vul_function.get_function_name()
                function_source_codes = vul_function.vul_source_codes
                asm_function = asm_function_dict.get(function_name)
                if not asm_function:
                    continue
                new_test_case = {
                    'CVE': tc.public_id,
                    'binary_path': binary_path,
                    'function_name': function_name,
                    'is_fixed': not tc.has_vul(),
                    'function_source_codes': function_source_codes,
                    'asm_instructions': asm_function.get_asm_codes(skip_function_def=False)[0],
                    'patches': []
                }
                for patch in vul_function.patches:
                    new_test_case['patches'].append({
                        'vul_snippet_codes': patch.vul_snippet_codes,
                        'fixed_snippet_codes': patch.fixed_snippet_codes
                    })
                new_test_cases.append(new_test_case)
        except Exception as e:
            print(f"process tc: {i}/{len(test_cases)} {tc.public_id}, error: {e}")
            continue
    print(len(new_test_cases))
    with open('new_test_cases.json', 'w') as f:
        import json
        json.dump(new_test_cases, f, indent=4)

    """
    1. 提取汇编指令
    2. 正规化处理源代码
    3. 提取补丁信息
    """


def main():
    generate_params()


if __name__ == '__main__':
    main()
