import re

import re


def normalize_asm_code(asm_code: str,
                       reg_token: str = "<REG>",  # 寄存器统一替换标记
                       num_token: str = "<NUM>",  # 数值统一替换标记
                       jump_token: str = "<JUMP>",  # 跳转指令统一替换标记
                       loc_token: str = "<LOC>",  # 位置（标签）统一替换标记
                       mem_token: str = "<MEM>",  # 内存访问统一替换标记
                       special_reg_token: str = "<SREG>"):  # 特殊寄存器标记
    """
    正规化汇编代码。
    :param asm_code: 待处理的汇编代码字符串。
    :return: 正规化后的汇编代码字符串。
    """
    # 转换为小写，保持一致性
    asm_code = asm_code.lower()

    # 移除注释
    asm_code = re.sub(r";.*", "", asm_code).split("#")[0]
    # 简化空格，保持格式整洁
    asm_code = re.sub(r"\s+", " ", asm_code).strip()

    # 移除所有的数据大小标记，如 'qword ptr'
    data_size_markers_pattern = r"\b(byte|word|dword|qword|tword)\s+ptr\b"
    asm_code = re.sub(data_size_markers_pattern, "", asm_code)

    # 如果是函数调用，不优化后续的替换
    if asm_code.startswith('call'):
        return asm_code

    # 替换寄存器为统一标记
    asm_code = re.sub(r"\br[\w\d]+\b", reg_token, asm_code)
    # 替换数字（立即数）为统一标记
    asm_code = re.sub(r"\b\d+\b|\b0x[a-f0-9]+\b", num_token, asm_code)
    # 简化内存访问，替换为统一标记
    asm_code = re.sub(r"\[[^\]]+\]", mem_token, asm_code)

    # 简化控制流指令，替换为跳转统一标记
    asm_code = re.sub(r"\bj(mp|e|z|nz|ne|g|ge|l|le|b|be|a|ae)\b", jump_token, asm_code)

    # 简化标签和符号引用，替换为位置统一标记
    asm_code = re.sub(r"\bloc(ret)?_[\w\d]+\b", loc_token, asm_code)
    asm_code = re.sub(r"\b[\w\d]+:\b", loc_token, asm_code)

    # 处理空格
    asm_code = asm_code.replace("  ", " ").replace(", ", ",")

    # 保留特定函数调用的结构化信息可能有助于理解代码的功能，这里以伪代码表示这一逻辑
    # asm_code = re.sub(r"call\s+[a-f0-9]+", "call " + func_token, asm_code)

    return asm_code
