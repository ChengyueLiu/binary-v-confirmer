from AUTO_COMPILE_functions import extract_asm
from bintools.general.file_tool import load_from_json_file

extract_asm("statistics/openssl.mapping",
            "/home/chengyue/test_cases/binary_sca_vul_confirmation/github_projects/openssl", "statistics/openssl.json")

mappings = load_from_json_file("statistics/openssl.json")
for function_name, mapping in mappings.items():
    src_dict = mapping["src_dict"]
    sub_function_name = list(src_dict.keys())[0]
    src_dict = src_dict[sub_function_name]['src_codes']
    asm_code_snippet_mappings = mapping["asm_code_snippet_mappings"]
    for snippet_mapping in asm_code_snippet_mappings:
        src_lines = [line
                     for line_num, line in src_dict.items()
                     if int(line_num) < snippet_mapping['src_line_number']]
        print(src_lines)
        print(snippet_mapping['asm_lines'])
        print()
        break

