from bintools.general.file_tool import load_from_json_file
from bintools.general.normalize import normalize_asm_lines


def analyze_asm_codes(asm_codes):
    """
    返回函数体的起始位置,和参数数量
    """
    param_count = 0
    body_start_index = 3
    for i, asm_code in enumerate(asm_codes[3:12], start=3):
        if asm_code in ('mov <MEM>,rdi', 'mov <MEM>,rsi', 'mov <MEM>,rdx', 'mov <MEM>,rcx', 'mov <MEM>,r8', 'mov <MEM>,r9'):
            param_count += 1
            body_start_index = i + 1

    return body_start_index, param_count


if __name__ == '__main__':
    path = r"C:\Users\chengyue\Desktop\projects\binary-v-confirmer\TestCases\feature_extraction\ida_pro_result.json"
    funcs = load_from_json_file(path)
    for f in funcs:
        asm_codes = f['first_block_asm']
        if len(asm_codes) < 10:
            continue

        normalized_asm_codes = normalize_asm_lines(asm_codes)
        body_part_start_index, param_count = analyze_asm_codes(normalized_asm_codes)
        print(f['name'])
        print(body_part_start_index,param_count)
        print(asm_codes[:body_part_start_index])
        print(normalized_asm_codes[:body_part_start_index])
        print(asm_codes[body_part_start_index:body_part_start_index + 3])
        print(normalized_asm_codes[body_part_start_index:body_part_start_index + 3])
        print()
