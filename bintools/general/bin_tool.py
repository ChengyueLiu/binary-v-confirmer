def analyze_asm_codes(normalized_asm_codes):
    """
    返回函数体的起始位置,和参数数量
    """
    param_count = 0
    body_start_index = 1
    start_flag = False
    for i, asm_code in enumerate(normalized_asm_codes[1:20], start=1):
        # if asm_code in (
        #         'mov <MEM>,rdi',
        #         'mov <MEM>,rsi',
        #         'mov <MEM>,rdx',
        #         'mov <MEM>,rcx',
        #         'mov <MEM>,r8',
        #         'mov <MEM>,r9',
        #         # 以下是补充的
        #         'mov <MEM>,esi',
        #         'mov <MEM>,edx',
        #         'mov <MEM>,edi',
        #         'mov <MEM>,ecx',
        #         'movsd <MEM>,xmm0',
        #         'movss <MEM>,xmm0'
        # ):
        if asm_code.split(',')[0] in (
            'mov <MEM>',
            'movsd <MEM>',
            'movss <MEM>',
        ):
            param_count += 1
            body_start_index = i + 1
            start_flag = True
        elif start_flag:
            break
    if param_count >= 6:
        param_count = 6
    return body_start_index, param_count
