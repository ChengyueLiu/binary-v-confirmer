import re

import re


def normalize_asm_code(asm_code: str,
                       reg_token: str = "<REG>",  # 寄存器统一替换标记
                       num_token: str = "<NUM>",  # 数值统一替换标记
                       jump_token: str = "<JUMP>",  # 跳转指令统一替换标记
                       loc_token: str = "<LOC>",  # 位置（标签）统一替换标记
                       mem_token: str = "<MEM>",  # 内存访问统一替换标记
                       ):
    """
    正规化汇编代码。
    :param asm_code: 待处理的汇编代码字符串。
    :return: 正规化后的汇编代码字符串。
    """
    # 如果输入的是原始的行信息，要先分割一下
    if "\t" in asm_code:
        asm_line_parts = asm_code.split("\t")
        if len(asm_line_parts) != 3:
            return None
        asm_code = asm_line_parts[-1]

    # 转换为小写，保持一致性
    # asm_code = asm_code.lower()

    # 移除注释
    asm_code = re.sub(r";.*", "", asm_code).split("#")[0]
    # 简化空格，保持格式整洁
    asm_code = re.sub(r"\s+", " ", asm_code).strip()

    # 移除所有的数据大小标记
    data_size_markers_pattern = r"\b(byte|word|dword|qword|tword|short)\s+ptr\b"
    asm_code = re.sub(data_size_markers_pattern, "", asm_code)

    # 简化内存访问，替换为统一标记
    asm_code = re.sub(r"\[[^\]]+\]", mem_token, asm_code)

    # 简化控制流指令，保留跳转逻辑，并处理跳转指令后的地址标记为 <LOC>
    asm_code = re.sub(r"\bj(mp|e|z|nz|ne|g|ge|l|le|b|be|a|ae)\s+(short\s+)?[0-9a-f]+\s+<[^>]+>",
                      jump_token + " " + loc_token, asm_code)

    # # 移除jmp指令后的short关键字，并保留跳转标签
    asm_code = re.sub(r"\b(j(mp|e|z|nz|ne|g|ge|l|le|b|be|a|ae))\s+short\s+[0-9a-f]+\s+<([^>]+)>", jump_token + r" <\3>",
                      asm_code)

    # 移除call和jump指令后的直接内存地址，保留函数名和跳转标签，处理可选的偏移量
    asm_code = re.sub(r"\bcall\s+[0-9a-f]+\s+<([^>]+)>", r"call <\1>", asm_code)

    # 移除short
    asm_code = asm_code.replace(" short ", " ")
    # 对于带有偏移量的标签，特殊处理以保留偏移量信息
    asm_code = re.sub(r"<([^+]+)\+\S+>", r"<\1+OFFSET>", asm_code)
    # 处理空格和逗号
    asm_code = asm_code.replace("  ", " ").replace(", ", ",")

    return asm_code
