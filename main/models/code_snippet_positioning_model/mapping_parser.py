import re

from loguru import logger


class MappingParser:
    def __init__(self):
        self.raw_lines = []
        self.file_path = ""
        self.file_type = ""
        self._sections = {}
        self._functions = []
        self.functions = []
        self.path_start = "/home/chengyue/"

    def parse(self, mapping_file_path):
        # parse lines
        with open(mapping_file_path, 'r', encoding='utf-8') as f:
            self.raw_lines = [line.rstrip() for line in f.readlines()]
        for line in self.raw_lines:
            if line.strip():
                parts = line.split()
                file_path = parts[0]
                self.file_type = parts[-1]
                self.file_path = file_path[:-1]
                break

        # 拆分节
        self._split_sections()
        # 拆分函数
        self._split_functions(mapping_file_path)
        # 解析函数
        self._parse_functions()

    def reset(self):
        self.raw_lines = []
        self.file_path = ""
        self.file_type = ""
        self._sections = {}
        self._functions = []
        self.functions = []

    def dump(self, json_file_path):
        import json
        with open(json_file_path, 'w', encoding='utf-8') as f:
            result = {
                "file_path": self.file_path,
                "file_type": self.file_type,
                "functions": self.functions
            }
            json.dump(result, f, indent=4, ensure_ascii=False)

    def _split_sections(self):
        """

        这些节（sections）在ELF（Executable and Linkable Format）文件中扮演特定的角色，主要用于控制程序的加载、链接和执行。以下是每个节的基本用途：

        .init
        用途：包含程序初始化前需要执行的代码。
        详情：在程序启动和main函数执行之前，init节中的代码会被自动执行。这部分通常由编译器和链接器自动生成，用于执行诸如全局构造函数之类的初始化任务。

        .plt (Procedure Linkage Table)
        用途：支持动态链接和函数调用。
        详情：plt节用于动态链接的程序中，为动态链接库中的函数提供一个跳转表。当程序调用一个动态链接库（如共享库.so文件）中的函数时，控制权首先跳转到plt中相应的条目，然后再由这里跳转到实际的函数实现。这允许在运行时解析函数的真正地址。

        .plt.got (Procedure Linkage Table for Global Offset Table)
        用途：与.plt相似，但专用于访问全局偏移表（GOT）中的项。
        详情：plt.got节与全局偏移表（GOT）结合使用，用于动态解析程序中使用的全局变量和函数的地址。

        .plt.sec
        用途：这是一个特定于实现的节，用于支持特定类型的PLT条目。
        详情：plt.sec节的具体用途可能因工具链和操作系统的具体实现而异，但它通常与.plt节相关，用于优化或特殊情况下的函数调用。

        .text
        用途：包含程序的主要执行代码。
        详情：text节是ELF文件中最重要的部分之一，包含了程序的机器指令（即程序实际执行的代码）。这个节在内存中是只读的，以防止程序在运行时修改其自身的代码。

        .fini
        用途：包含程序终止前需要执行的代码。
        详情：在程序结束和exit函数被调用之前，fini节中的代码会被自动执行。这部分代码通常由编译器和链接器自动生成，用于执行诸如全局析构函数之类的清理任务。
        这些节在链接和加载过程中起着关键作用，它们使得程序能够在运行时动态地链接到其它库，同时也包含了程序开始和结束时需要执行的初始化和终结代码。

        :return:
        """
        current_section = None
        for line in self.raw_lines[1:]:
            if line.startswith('Disassembly of section .'):
                current_section = line.split()[-1][:-1]
            if current_section:
                if (current_section_lines := self._sections.get(current_section)) is None:
                    self._sections[current_section] = current_section_lines = []
                current_section_lines.append(line)

    def _split_functions(self,mapping_file_path):
        text_section_lines = self._sections.get('.text')
        if text_section_lines is None:
            for section in self._sections:
                if section.startswith('.text'):
                    text_section_lines = self._sections[section]
                    # logger.warning(f"use {section} as .text section.")
                    break
        if text_section_lines is None:
            logger.warning(f"No .text section found in the mapping file: {mapping_file_path}")
            return
        text_section_lines = text_section_lines[1:]
        functions = []
        current_function_lines = []
        for line in text_section_lines[1:]:
            if is_function_start_flag(line):
                if len(current_function_lines) > 1:
                    functions.append(current_function_lines)
                    current_function_lines = []
            current_function_lines.append(line)
        if current_function_lines:
            functions.append(current_function_lines)
        self._functions = functions

    def _parse_functions(self):

        for function_lines in self._functions:
            # 函数地址行
            address_line = function_lines[0]
            # 函数名
            function_name = address_line.split()[1][1:-2]

            sub_functions = []
            current_sub_function_name = ""
            current_sub_function_lines = []
            for line in function_lines[1:]:
                if line.endswith('():'):
                    if current_sub_function_name and current_sub_function_lines:
                        sub_functions.append({
                            "function_name": current_sub_function_name,
                            "snippets": split_snippets(current_sub_function_lines, self.path_start)
                        })
                    current_sub_function_lines = []
                    current_sub_function_name = line[:-3]
                    continue
                current_sub_function_lines.append(line)

            if current_sub_function_name and current_sub_function_lines:
                sub_functions.append({
                    "function_name": current_sub_function_name,
                    "snippets": split_snippets(current_sub_function_lines, self.path_start)
                })

            self.functions.append({
                "function_name": function_name,
                "sub_functions": sub_functions
            })


def is_function_start_flag(line):
    pattern = r'^[0-9a-f]+\s+<[^>]+>:'
    return bool(re.match(pattern, line))


def split_snippets(lines, path_start="/home/chengyue/"):
    snippets = []
    line_position = ""
    current_snippet_lines = []
    for i, line in enumerate(lines):
        if line.startswith(path_start) or line.startswith("/usr/"):
            if line_position and current_snippet_lines:
                snippets.append({
                    "line_position": line_position,
                    **split_src_asm_lines(current_snippet_lines)
                })
                current_snippet_lines = []
            line_position = line
            continue
        current_snippet_lines.append(line)
    if line_position and current_snippet_lines:
        snippets.append({
            "line_position": line_position,
            **split_src_asm_lines(current_snippet_lines)
        })

    return snippets


def split_src_asm_lines(lines):
    for i, line in enumerate(lines):
        if is_assembly_line(line):
            return {
                "src_lines": lines[:i],
                "asm_lines": lines[i:]
            }


def is_assembly_line(line):
    # 去除前后空格
    trimmed_line = line.strip()

    # 检查行中是否包含冒号
    if ':' not in trimmed_line:
        return False

    # 获取冒号之前的部分
    address_part = trimmed_line.split(':')[0]

    # 尝试解释为地址值
    try:
        int(address_part, 16)
        return True
    except ValueError:
        return False
