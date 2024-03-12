import json
import os
import subprocess
from typing import List

from loguru import logger
from tqdm import tqdm

import re


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


class NewMappingParser:
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
                file_path, _, _, self.file_type = line.split()
                self.file_path = file_path[:-1]
                break

        # 拆分节
        self._split_sections()
        # 拆分函数
        self._split_functions()
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

    def _split_functions(self):
        text_section_lines = self._sections.get('.text')[1:]
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


class AutoDataPreparer:
    def __init__(self,
                 script_path: str,
                 base_output_dir: str,
                 mapping_output_dir: str,
                 parsed_mapping_file_dir: str,
                 project_name: str,
                 target_tags: List[str]):
        self.script_path = script_path
        self.base_output_dir = base_output_dir
        self.mapping_output_dir = mapping_output_dir
        self.parsed_mapping_file_dir = parsed_mapping_file_dir

        self.project_name = project_name
        self.target_tags = target_tags

    def prepare(self, run_compile=True, objdump=True, parse=True, merge=True):
        # 第一层进度条：处理target_tags
        for tag in tqdm(self.target_tags, desc="Processing tags"):
            logger.info(f"Processing tag {tag}...")
            if run_compile:
                success, output = self.run_auto_compile_script(tag)
                if not success:
                    logger.error(f"Failed to compile the project with tag {tag}. Error: {output}")
                    continue  # 跳过当前循环的剩余部分
                logger.info(f"Project compiled successfully with tag {tag}.")

            mapping_pairs = self.generate_mapping_file_paths(tag)
            if len(mapping_pairs) == 0:
                logger.warning(f"No mapping files found for tag {tag}. Skipping...")

            # 第二层进度条：运行objdump命令
            if objdump:
                with tqdm(total=len(mapping_pairs), desc=f"Running objdump for {tag}") as pbar_objdump:
                    for bin_file_path, mapping_file_path in mapping_pairs:
                        success, output = self.run_objdump_script(bin_file_path, mapping_file_path)
                        if not success:
                            logger.warning(f"Failed to run objdump on {bin_file_path}. Error: {output}")
                        pbar_objdump.update(1)  # 即使失败也更新进度条

            # 第三层进度条：解析mapping文件
            if parse:
                with tqdm(total=len(mapping_pairs), desc=f"Parsing mappings for {tag}") as pbar_parsing:
                    for _, mapping_file_path in mapping_pairs:
                        if not os.path.exists(mapping_file_path):
                            logger.error(f"Mapping file not found: {mapping_file_path}")
                            pbar_parsing.update(1)  # 文件不存在也更新进度条
                            continue  # 跳过不存在的文件
                        parsed_mapping_file_path = mapping_file_path.replace(self.mapping_output_dir,
                                                                             self.parsed_mapping_file_dir)
                        file_dir, file_name = os.path.split(parsed_mapping_file_path)
                        os.makedirs(file_dir, exist_ok=True)

                        parser = NewMappingParser(mapping_file_path)
                        parser.parse()
                        parser.dump(f"{parsed_mapping_file_path}.json")
                        pbar_parsing.update(1)
        if merge:
            logger.info("All tags processed, merging mapping files...")
            self.merge_mapping_jsons()
            logger.info("Mapping files merged successfully.")
        logger.info("Data preparation completed.")

    def run_auto_compile_script(self, tag=None):
        """
        Runs the provided shell script with the given project name and optional tag.

        Parameters:
        - project_name: The name of the project (e.g., 'openssl', 'redis', 'libpng', 'vim').
        - tag: The optional tag name to checkout before compiling. If None, no tag is used.

        Returns:
        - A tuple (success: bool, output: str) indicating whether the script ran successfully
          and the output of the script.
        """
        # 构造脚本命令
        command = [self.script_path, self.project_name]

        # 如果提供了tag，则添加到命令中
        if tag:
            command.append(tag)

        try:
            # 使用subprocess.run执行脚本，捕获输出和错误
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            # 如果脚本执行成功，check=True会确保只有在退出码为0时才会继续执行
            return True, result.stdout
        except subprocess.CalledProcessError as e:
            # 如果脚本执行失败，返回失败状态和错误输出
            return False, e.stdout

    def run_objdump_script(self, source_path, target_path):
        """
        Runs the objdump command on the specified source file and redirects the output to the target file.

        Parameters:
        - source_path: The path to the binary file to analyze with objdump.
        - target_path: The path where the objdump output will be saved.

        Returns:
        - A tuple (success: bool, message: str) indicating whether the command ran successfully
          and the command's output or error message.
        """
        # objdump -d <source_path> --source --line-numbers -M intel > <target_path>
        command = [
            'objdump',
            '-d',
            source_path,
            '--source',
            '--line-numbers',
            '-M', 'intel'  # 添加这行来指定Intel风格
        ]

        try:
            # Open the target file in write mode
            with open(target_path, 'w') as file:
                # Execute the objdump command and redirect the output to the target file
                subprocess.run(command, check=True, stdout=file, stderr=subprocess.PIPE, text=True)
            return True, "Command executed successfully."
        except subprocess.CalledProcessError as e:
            # If the command fails, return False and the error output
            return False, e.stderr

    def generate_mapping_file_paths(self, tag):
        mapping_pairs = []
        for opt in ['O0', 'O1', 'O2', 'O3']:
            elf_file_paths = []
            project_output_dir = f"{self.base_output_dir}/{self.project_name}/{tag}/{opt}"
            bin_dir_path = f"{project_output_dir}/bin"
            elf_file_paths.extend(self.find_elf_files(bin_dir_path))
            lib64_dir_path = f"{project_output_dir}/lib"
            elf_file_paths.extend(self.find_elf_files(lib64_dir_path))
            lib64_dir_path = f"{project_output_dir}/lib64"
            elf_file_paths.extend(self.find_elf_files(lib64_dir_path))

            mapping_output_dir = f"{self.mapping_output_dir}/{self.project_name}/{tag}/{opt}"
            for elf_file_path in elf_file_paths:
                mapping_file_path = elf_file_path.replace(project_output_dir, mapping_output_dir)
                mapping_file_path = f"{mapping_file_path}.mapping"
                file_dir, file_name = os.path.split(mapping_file_path)
                os.makedirs(file_dir, exist_ok=True)
                mapping_pairs.append((elf_file_path, mapping_file_path))

        return mapping_pairs

    def find_elf_files(self, directory):
        """
        Recursively searches the given directory for ELF files and returns their paths.

        Parameters:
        - directory: The directory to search for ELF files.

        Returns:
        - A list of paths to ELF files found in the directory and its subdirectories.
        """
        elf_files = []
        if os.path.exists(directory):
            for file in os.listdir(directory):
                path = os.path.join(directory, file)
                if (os.path.isfile(path)
                    and not os.path.islink(path)
                    and os.access(path, os.X_OK)) \
                        and os.path.getsize(path) > 100:
                    elf_files.append(path)
        else:
            # logger.warning(f"Directory not found: {directory}")
            pass
        return elf_files

    def merge_mapping_jsons(self):
        mapping_json_dict = {}
        for root, dirs, files in os.walk(self.parsed_mapping_file_dir):
            for file in files:
                if file.endswith('.json'):
                    file_path = os.path.join(root, file)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        mapping_json_dict[file] = data
        with open(f'{self.parsed_mapping_file_dir}/merged_mapping.json', 'w', encoding='utf-8') as f:
            json.dump(mapping_json_dict, f, indent=4, ensure_ascii=False)


if __name__ == '__main__':
    script_path = "/home/chengyue/test_cases/binary_sca_vul_confirmation/github_projects/auto_compile.sh"
    project_name = "openssl"
    base_output_dir = "/home/chengyue/test_cases/binary_sca_vul_confirmation/compiled_projects"
    mapping_output_dir = "/home/chengyue/test_cases/binary_sca_vul_confirmation/src_asm_mappings"
    parsed_mapping_file_dir = "/home/chengyue/test_cases/binary_sca_vul_confirmation/parsed_mappings"
    target_tags = ['OpenSSL_0_9_6', 'OpenSSL_0_9_6a', 'OpenSSL_0_9_6c', 'OpenSSL_0_9_6d', 'OpenSSL_0_9_6e',
                   'OpenSSL_0_9_6f', 'OpenSSL_0_9_6i', 'OpenSSL_0_9_6j', 'OpenSSL_0_9_6k', 'OpenSSL_0_9_6l',
                   'OpenSSL_0_9_6m', 'OpenSSL_0_9_7', 'OpenSSL_0_9_7-beta3', 'OpenSSL_0_9_7a', 'OpenSSL_0_9_7b',
                   'OpenSSL_0_9_7c', 'OpenSSL_0_9_7d', 'OpenSSL_0_9_7f', 'OpenSSL_0_9_7h', 'OpenSSL_0_9_7k',
                   'OpenSSL_0_9_7l', 'OpenSSL_0_9_8', 'OpenSSL_0_9_8a', 'OpenSSL_0_9_8c', 'OpenSSL_0_9_8d',
                   'OpenSSL_0_9_8f', 'OpenSSL_0_9_8g', 'OpenSSL_0_9_8h', 'OpenSSL_0_9_8i', 'OpenSSL_0_9_8j',
                   'OpenSSL_0_9_8k', 'OpenSSL_0_9_8m', 'OpenSSL_0_9_8n', 'OpenSSL_0_9_8o', 'OpenSSL_0_9_8p',
                   'OpenSSL_0_9_8q', 'OpenSSL_0_9_8r', 'OpenSSL_0_9_8s', 'OpenSSL_0_9_8t', 'OpenSSL_0_9_8u',
                   'OpenSSL_0_9_8v', 'OpenSSL_0_9_8w', 'OpenSSL_0_9_8x', 'OpenSSL_0_9_8y', 'OpenSSL_0_9_8za',
                   'OpenSSL_0_9_8zb', 'OpenSSL_0_9_8zc', 'OpenSSL_0_9_8zd', 'OpenSSL_0_9_8zf', 'OpenSSL_0_9_8zg',
                   'OpenSSL_0_9_8zh', 'OpenSSL_1_0_0', 'OpenSSL_1_0_0a', 'OpenSSL_1_0_0b', 'OpenSSL_1_0_0c',
                   'OpenSSL_1_0_0d', 'OpenSSL_1_0_0e', 'OpenSSL_1_0_0f', 'OpenSSL_1_0_0g', 'OpenSSL_1_0_0h',
                   'OpenSSL_1_0_0i', 'OpenSSL_1_0_0j', 'OpenSSL_1_0_0k', 'OpenSSL_1_0_0l', 'OpenSSL_1_0_0m',
                   'OpenSSL_1_0_0n', 'OpenSSL_1_0_0o', 'OpenSSL_1_0_0p', 'OpenSSL_1_0_0r', 'OpenSSL_1_0_0s',
                   'OpenSSL_1_0_0t', 'OpenSSL_1_0_1', 'OpenSSL_1_0_1a', 'OpenSSL_1_0_1c', 'OpenSSL_1_0_1d',
                   'OpenSSL_1_0_1f', 'OpenSSL_1_0_1g', 'OpenSSL_1_0_1h', 'OpenSSL_1_0_1i', 'OpenSSL_1_0_1j',
                   'OpenSSL_1_0_1k', 'OpenSSL_1_0_1m', 'OpenSSL_1_0_1n', 'OpenSSL_1_0_1o', 'OpenSSL_1_0_1p',
                   'OpenSSL_1_0_1q', 'OpenSSL_1_0_1r', 'OpenSSL_1_0_1s', 'OpenSSL_1_0_1t', 'OpenSSL_1_0_1u',
                   'OpenSSL_1_0_2', 'OpenSSL_1_0_2a', 'OpenSSL_1_0_2b', 'OpenSSL_1_0_2c', 'OpenSSL_1_0_2d',
                   'OpenSSL_1_0_2e', 'OpenSSL_1_0_2f', 'OpenSSL_1_0_2g', 'OpenSSL_1_0_2h', 'OpenSSL_1_0_2i',
                   'OpenSSL_1_0_2j', 'OpenSSL_1_0_2k', 'OpenSSL_1_0_2m', 'OpenSSL_1_0_2n', 'OpenSSL_1_0_2o',
                   'OpenSSL_1_0_2p', 'OpenSSL_1_0_2q', 'OpenSSL_1_0_2r', 'OpenSSL_1_0_2s', 'OpenSSL_1_0_2t',
                   'OpenSSL_1_0_2u', 'OpenSSL_1_1_0', 'OpenSSL_1_1_0a', 'OpenSSL_1_1_0b', 'OpenSSL_1_1_0c',
                   'OpenSSL_1_1_0d', 'OpenSSL_1_1_0e', 'OpenSSL_1_1_0g', 'OpenSSL_1_1_0h', 'OpenSSL_1_1_0i',
                   'OpenSSL_1_1_0j', 'OpenSSL_1_1_0k', 'OpenSSL_1_1_0l', 'OpenSSL_1_1_1', 'OpenSSL_1_1_1a',
                   'OpenSSL_1_1_1c', 'OpenSSL_1_1_1d', 'OpenSSL_1_1_1e', 'OpenSSL_1_1_1g', 'OpenSSL_1_1_1h',
                   'OpenSSL_1_1_1i', 'OpenSSL_1_1_1j', 'OpenSSL_1_1_1k', 'OpenSSL_1_1_1l', 'OpenSSL_1_1_1m',
                   'OpenSSL_1_1_1n', 'OpenSSL_1_1_1o', 'OpenSSL_1_1_1p', 'OpenSSL_1_1_1q', 'OpenSSL_1_1_1t',
                   'OpenSSL_1_1_1u', 'OpenSSL_1_1_1v', 'OpenSSL_1_1_1w', 'openssl-3.0.0', 'openssl-3.0.1',
                   'openssl-3.0.10', 'openssl-3.0.11', 'openssl-3.0.12', 'openssl-3.0.13', 'openssl-3.0.2',
                   'openssl-3.0.3', 'openssl-3.0.4', 'openssl-3.0.5', 'openssl-3.0.6', 'openssl-3.0.7', 'openssl-3.0.8',
                   'openssl-3.0.9', 'openssl-3.1.0', 'openssl-3.1.1', 'openssl-3.1.2', 'openssl-3.1.3', 'openssl-3.1.4',
                   'openssl-3.1.5', 'openssl-3.2.0', 'openssl-3.2.1']
    preparer = AutoDataPreparer(script_path,
                                base_output_dir,
                                mapping_output_dir,
                                parsed_mapping_file_dir,
                                project_name,
                                target_tags)
    preparer.prepare(run_compile=False)
