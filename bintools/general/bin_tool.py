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