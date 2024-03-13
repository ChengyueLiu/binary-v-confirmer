import re


def normalize_ams_code(asm_code: str,
                       reg_token: str,
                       num_token: str,
                       jump_token: str,
                       loc_token: str):
    """
    Normalize assembly code
    :param asm_code: Intel assembly code
    :return:
    """

    # 正规化处理汇编代码
    # 替换连续的空格为单个空格
    asm_code = re.sub(r"\s+", " ", asm_code).strip()
    # 移除注释
    asm_code = re.sub(r";.*", "", asm_code)
    # 替换寄存器和立即数
    asm_code = re.sub(r"\br[\w\d]+\b", reg_token, asm_code)
    asm_code = re.sub(r"\b\d+\b", num_token, asm_code)
    # 简化控制流指令
    asm_code = re.sub(r"\bj(mp|e|z|nz|ne|g|ge|l|le)\b", jump_token, asm_code)
    # 简化跳转标签和地址
    asm_code = re.sub(r"\bloc(ret)?_[\w\d]+\b", loc_token, asm_code)
