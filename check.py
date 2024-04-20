import ast
import os.path

from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file


def split_log_lines(lines):
    lines = lines[4:-7]
    tc_lines_list = []
    cur_tc_lines = []
    for line in lines:
        line = line.strip()
        if not line and cur_tc_lines:
            tc_lines_list.append(cur_tc_lines)
            cur_tc_lines = []
            continue
        line = line.split(' -', 1)[1]

        cur_tc_lines.append(line)
    if cur_tc_lines:
        tc_lines_list.append(cur_tc_lines)

    return tc_lines_list


def parse_tc_lines(tc_lines):
    public_id = ""
    objdump_file = ""
    check_result = ""
    vul_functions = []
    vul_functions_in_data_items = []
    bin_vul_functions = []
    for line in tc_lines:
        line = line.strip()
        if line.startswith('confirm: '):
            public_id = line.split()[-1]
        elif line.startswith('extracting asm functions from '):
            objdump_file = line.split()[-1]
        elif line.startswith('check result: '):
            check_result = line.split()[-1]
        elif line.startswith('vul functions: '):
            vul_functions = ast.literal_eval(line.split('vul functions: ')[-1])
        elif line.startswith('vul functions in data items: '):
            vul_functions_in_data_items = ast.literal_eval(line.split('vul functions in data items: ')[-1])
        elif line.startswith('bin vul functions: '):
            bin_vul_functions = ast.literal_eval(line.split('bin vul functions: ')[-1])
        else:
            pass

    tc_result = {
        "public_id": public_id,
        "objdump_file": objdump_file,
        "check_result": check_result,
        "vul_functions": vul_functions,
        "vul_functions_in_data_items": vul_functions_in_data_items,
        "bin_vul_functions": bin_vul_functions
    }
    return tc_result


def check_function_exists(function_name, objdump_file_path):
    if function_name.startswith('*'):
        function_name = function_name[1:]
    asm_function_dict = parse_objdump_file(objdump_file_path, ignore_warnings=True)
    return function_name in asm_function_dict


def check_experiment_log(log_path):
    with open(log_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    tc_lines_list = split_log_lines(lines)
    count = 0
    for i, tc_lines in enumerate(tc_lines_list, 1):
        tc_result = parse_tc_lines(tc_lines)
        if not tc_result['vul_functions_in_data_items'] and tc_result['bin_vul_functions']:
            print(i, tc_result['public_id'], tc_result['check_result'])
            objdump_file = tc_result['objdump_file']
            print(f"\tobjdump_file: {os.path.exists(objdump_file)}")
            print(f"\tvul functions: {tc_result['vul_functions']}")
            print(f"\tvul functions in data items: {tc_result['vul_functions_in_data_items']}")
            count += 1
            # objdump_file = tc_result['objdump_file']
            # print(f"\tvul functions: {tc_result['vul_functions']}")
            # for function_name in tc_result['vul_functions']:
            #     print(f"\t{function_name}: {check_function_exists(function_name, objdump_file)}")

    print(count)


if __name__ == '__main__':
    path = 'logs/experiment_20240419_135914.log'
    check_experiment_log(path)
