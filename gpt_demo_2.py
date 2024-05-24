from typing import List

from bintools.general.normalize import normalize_asm_lines, normalize_src_lines, remove_comments
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
                for patch in vul_function.patches:
                    new_test_case = {
                        'CVE': tc.public_id,
                        'binary_path': binary_path,
                        'function_name': function_name,
                        'is_fixed': not tc.has_vul(),
                        'function_source_codes': function_source_codes,
                        'vul_snippet_codes': patch.vul_snippet_codes,
                        'fixed_snippet_codes': patch.fixed_snippet_codes,
                        'asm_instructions': asm_function.get_asm_codes(skip_function_def=False)
                    }
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


# You are an expert in analyzing assembly instructions and source code. Your task is to determine if the patch is present in the assembly instructions of a function. This task involves three key steps:
#
# Understand the changes introduced by the patch.
# Identify the segment of the provided assembly instructions that corresponds to the changed part of the source code based on contextual information.
# Determine whether the located segment contains the patch by analyzing the changes brought by the patch and the identified assembly instruction segment.
def make_prompt(assembly_instructions, source_code_before, patches):
    prompt_text = f"""
You are an expert in analyzing assembly instructions and source code. 

Your task is to determine if the patch is present in the assembly instructions of a function. This task involves three key steps:
1. Understand the changes introduced by the patch.
2. Identify the segment of the provided assembly instructions that corresponds to the changed part of the source code based on the given inputs.
3. Determine whether the located segment contains the patch by analyzing the changes brought by the patch and the identified assembly instruction segment.
4. Note: When analyzing the assembly instructions, do not simply check if the logic introduced by the patch is present. The same logic might have existed before the patch was applied. After introducing new logic, there should be an additional set of instructions compared to the original. 

**Inputs**:
- Source Code Before Patch: "{source_code_before}"
- Patches(json): {patches}
- Assembly Instructions: "{assembly_instructions}"

You MUST read the inputs carefully and use Chain of Thought reasoning to determine the answer. Mimic answering in the background five times and provide the most frequently appearing answer. 

Furthermore, please strictly adhere to the output format specified below:

**Output Format**:
- contain patch: 'Yes' or 'No'
- corresponding assembly instruction segment: (Example format: jg <LOC> cmp eax,0x301 jge <LOC> cmp eax,0x201 je <LOC> cmp eax,0x202 je <LOC> jmp <LOC> lea rsi,<MEM> lea rcx,<MEM> lea rdx,<MEM>)
- key reason: (give the key reason for your judgment)
"""
    return prompt_text


def list_to_str(l):
    return " ".join([s.strip() for s in l])


def normalize_asm(asm: List[str]):
    return list_to_str(normalize_asm_lines(asm))


def normalize_src(src: List[str]):
    return remove_comments(list_to_str(normalize_src_lines(src)))


def normalize_patches(patches):
    for patch in patches:
        patch['vul_snippet_codes'] = normalize_src(patch['vul_snippet_codes'])
        patch['fixed_snippet_codes'] = normalize_src(patch['fixed_snippet_codes'])
    return patches


def generate_input():
    with open('new_test_cases_demo.json', 'r') as f:
        import json
        new_test_cases = json.load(f)
    for i, tc in enumerate(new_test_cases, 1):
        prompt = make_prompt(normalize_asm(tc['asm_instructions']),
                             normalize_src(tc['function_source_codes']),
                             normalize_patches(tc['patches']))

        print(i, 'test: ', tc['CVE'], tc['function_name'], 'in binary: ', tc['binary_path'])
        print(prompt)
        print('ground truth:', tc['is_fixed'])
        print()


def main():
    # generate_params()
    generate_input()


if __name__ == '__main__':
    main()
