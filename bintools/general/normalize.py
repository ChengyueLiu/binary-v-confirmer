import re


def normalized_asm_lines(lines):
    from main.interface import SpecialToken
    normalized_asm_lines = [normalized_code for code in lines if (normalized_code := normalize_asm_code(code,
                                                                                                        reg_token=SpecialToken.ASM_REG.value,
                                                                                                        num_token=SpecialToken.ASM_NUM.value,
                                                                                                        jump_token=SpecialToken.ASM_JUMP.value,
                                                                                                        loc_token=SpecialToken.ASM_LOC.value,
                                                                                                        mem_token=SpecialToken.ASM_MEM.value))]
    if " ".join(normalized_asm_lines[:3]) == "endbr64 push rbp mov rbp,rsp":
        normalized_asm_lines = normalized_asm_lines[3:]
    return normalized_asm_lines


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


def normalize_src_lines(lines):
    """
    移除注释行和空行，移除两端空白字符
    """
    normalized_lines = []
    for line in lines:
        line = line.strip()
        if (line.startswith(("/*", "* ", "//"))  # 注释行开头
                or line.endswith("*/")  # 注释行结尾
                or line in ["", "*"]):  # 空行
            continue
        normalized_lines.append(line)
    return normalized_lines


def remove_comments(text):
    """ remove c-style comments.
        text: blob of text with comments (can include newlines)
        returns: text with comments removed
    """
    pattern = r"""
                            ##  --------- COMMENT ---------
           /\*              ##  Start of /* ... */ comment
           [^*]*\*+         ##  Non-* followed by 1-or-more *'s
           (                ##
             [^/*][^*]*\*+  ##
           )*               ##  0-or-more things which don't start with /
                            ##    but do end with '*'
           /                ##  End of /* ... */ comment
         |                  ##  -OR-  various things which aren't comments:
           (                ## 
                            ##  ------ " ... " STRING ------
             "              ##  Start of " ... " string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^"\\]       ##  Non "\ characters
             )*             ##
             "              ##  End of " ... " string
           |                ##  -OR-
                            ##
                            ##  ------ ' ... ' STRING ------
             '              ##  Start of ' ... ' string
             (              ##
               \\.          ##  Escaped char
             |              ##  -OR-
               [^'\\]       ##  Non '\ characters
             )*             ##
             '              ##  End of ' ... ' string
           |                ##  -OR-
                            ##
                            ##  ------ ANYTHING ELSE -------
             .              ##  Anything other char
             [^/"'\\]*      ##  Chars which doesn't start a comment, string
           )                ##    or escape
    """
    regex = re.compile(pattern, re.VERBOSE | re.MULTILINE | re.DOTALL)
    noncomments = [m.group(2) for m in regex.finditer(text) if m.group(2)]

    return "".join(noncomments)


def normalize_strings(strs):
    """
    去重，并去除长度小于4的字符串
    """
    return list(set([normalized_string for string in strs
                     if len((normalized_string := string.strip())) >= 4]))
