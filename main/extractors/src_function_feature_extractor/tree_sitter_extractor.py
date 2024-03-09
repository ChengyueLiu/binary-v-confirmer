#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time : 2023/9/27 09:36
# @Author : Liu Chengyue
# @File : tree-sitter-parser.py
# @Software: PyCharm
import hashlib
import json
import multiprocessing
import os.path
import time
import traceback
from collections import deque
from typing import List

import git
from loguru import logger
from tree_sitter import Language, Parser, Node

from main.extractors.src_function_feature_extractor.constants import C_EXTENSION_SET, CPP_EXTENSION_SET, \
    FILTER_DIR_NAME_SET, SUPPORTED_EXTENSION_SET
from main.extractors.src_function_feature_extractor.entities import FileFeature, NodeFeature, NodeType, ProjectFeature, \
    MayOOMException
from setting.extractor_settings import FEATURE_EXTRACTOR_MEMORY_LIMIT, CAL_COMMIT_TIME
from setting.paths import TREE_SITTER_LANGUAGE_FILE_PATH

C_LANGUAGE = Language(TREE_SITTER_LANGUAGE_FILE_PATH, 'c')
CPP_LANGUAGE = Language(TREE_SITTER_LANGUAGE_FILE_PATH, 'cpp')


def cal_normalized_hash(lines):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    string = "".join(lines)
    normalized_string = "".join(
        string.replace("\n", "")
        .replace("\r", "")
        .replace("\t", "")
        .replace("{", "")
        .replace("}", "")
        .split(" ")
    ).lower()

    string_hash = hashlib.md5(normalized_string.encode()).hexdigest()
    return string_hash


def calculate_file_md5(file_path):
    """计算文件的SHA-256哈希值"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class FileFeatureExtractor:

    def __init__(self, file_path, contents: List[str] = None):
        # 最终结果
        self.result: FileFeature
        self.can_decode = True
        self.file_path = file_path

        # 初始化根节点
        if contents:
            self.root_node: Node = self.init_root_node_from_content(contents)
        else:
            self.root_node: Node = self.init_root_node_from_file()

        # 用于提取所有字符串时，判断字符串是否需要合并的一个标志
        self.all_string_merge_flag = False

        # 提取到的特征信息

        self.parse_error_line_numer_set = set()  # 解析错误的行号集合
        self.replacement_macro_dict = dict()
        self.node_features: List[NodeFeature] = []
        self.all_raw_strings = []

    def init_root_node_from_content(self, contents: List[str]):
        parser = Parser()
        if self.file_path.endswith(tuple(C_EXTENSION_SET)):
            parser.set_language(C_LANGUAGE)
        elif self.file_path.endswith(tuple(CPP_EXTENSION_SET)):
            parser.set_language(CPP_LANGUAGE)
        else:
            raise Exception(f"Unrecognized File Extension in Path: {self.file_path}")

        # 加载文件

        self.src_lines = contents
        self.tree = parser.parse(self.read_src_lines)
        return self.tree.root_node

    def init_root_node_from_file(self):
        parser = Parser()
        if self.file_path.endswith(tuple(C_EXTENSION_SET)):
            parser.set_language(C_LANGUAGE)
        elif self.file_path.endswith(tuple(CPP_EXTENSION_SET)):
            parser.set_language(CPP_LANGUAGE)
        else:
            raise Exception(f"Unrecognized File Extension in Path: {self.file_path}")

        # 加载文件
        try:
            with open(self.file_path) as f:
                self.src_lines = f.readlines()
        except Exception as e:
            if "'utf-8' codec can't decode" in str(e):
                self.can_decode = False
            else:
                logger.error(f'path: {self.file_path}, error: {e}')
            self.src_lines = []

        self.tree = parser.parse(self.read_src_lines)
        return self.tree.root_node

    def extract(self):
        # step 1: 提取字符串
        self.extract_node_strings(self.root_node)

        # step 2: 提取节点特征
        self.extract_node_features(self.root_node)

        # step 3: 生成最终结果
        self.result = FileFeature(
            # basic info
            self.file_path,
            self.can_decode,

            # features
            self.parse_error_line_numer_set,
            self.all_raw_strings,
            self.node_features,

            # statistics
            len(self.src_lines)
        )

    def dump_result(self, result_path):
        with open(result_path, 'w') as f:
            json.dump(self.result.custom_serialize(), f, ensure_ascii=False, indent=4)

    def read_src_lines(self, byte_offset, point):
        row, column = point
        if row >= len(self.src_lines) or column >= len(self.src_lines[row]):
            return None
        return self.src_lines[row][column:].encode('utf8')

    def extract_node_strings(self, node):
        stack = []  # 使用栈来模拟递归调用
        stack.append(node)

        while stack:
            current_node = stack.pop()

            # 处理当前节点
            if current_node.type == NodeType.string_content.value:
                node_content_lines = self.parse_node_content(current_node)
                string_content = node_content_lines[0]
                if self.all_string_merge_flag:
                    self.all_raw_strings[-1] = self.all_raw_strings[-1] + string_content
                else:
                    self.all_raw_strings.append(string_content)
                self.all_string_merge_flag = True
            else:
                if not (current_node.type == '"' or current_node.type == NodeType.string_literal.value):
                    self.all_string_merge_flag = False

                if current_node.type == NodeType.preproc_include.value:
                    continue

            # 将子节点压入栈中
            stack.extend(reversed(current_node.children))

    def extract_node_features(self, root_node):
        stack = [(root_node, 0)]

        while stack:
            current_node, level = stack.pop()

            # 起始行号（从1开始计数）
            node_line_number = current_node.start_point[0] + 1

            # 处理节点
            if current_node.type in {NodeType.preproc_include.value,
                                     NodeType.comment.value,
                                     NodeType.m_if,
                                     NodeType.m_ifdef,
                                     NodeType.m_ifndef,
                                     NodeType.m_elif,
                                     NodeType.m_else,
                                     NodeType.m_endif,
                                     }:
                continue

            # 跳过识别错误的节点
            if current_node.type == NodeType.string_content.error.value:
                self.parse_error_line_numer_set.add(node_line_number)

            # 1. 记录替换宏：
            if current_node.type == NodeType.preproc_def.value:
                self.parse_preproc_def_node(current_node)
                continue

            # 2. 识别函数
            elif current_node.type in {NodeType.function_definition.value}:
                self.parse_function_definition_node(current_node)
                continue

            # 3. 识别变量声明
            elif current_node.type in {NodeType.declaration.value, NodeType.function_declarator.value}:
                self.parse_declaration_node(current_node)
                continue

            # 将子节点按逆序压入栈中
            stack.extend((child_node, level + 1) for child_node in reversed(current_node.children))

    def parse_preproc_def_node(self, node):
        try:
            # print(node.sexp())
            # name
            replacement_macro_name: str = self.parse_node_content(node.child_by_field_name('name'))[0]
            # value
            value_node = node.child_by_field_name('value')
            if value_node:
                replacement_macro_value: str = self.parse_node_content(value_node)[0]
                # 只记录字符串替换, 移除掉双引号
                if replacement_macro_value and replacement_macro_value.startswith(
                        '"') and replacement_macro_value.endswith('"'):
                    # print(f'{replacement_macro_name} | {replacement_macro_value}')
                    self.replacement_macro_dict[replacement_macro_name] = replacement_macro_value[1:-1]
        except Exception as e:
            logger.error(e)

    def process_node_name(self, node_name):
        if "(" in node_name:
            node_name = node_name.split('(')[0]

        node_name = node_name.replace("* ", "")
        return node_name

    def parse_declaration_node(self, node):
        """
        解析声明类型
        :param node:
        :return:
        """

        declarator_node = node.child_by_field_name('declarator')

        # 解析节点类型，名称
        identifier_node = declarator_node.child_by_field_name('declarator')
        if not identifier_node:
            return

        node_type = identifier_node.type
        node_name = self.parse_node_content(identifier_node)[0]
        # 这种是识别错了的
        if node_type == "function_declarator":
            if node_name.startswith("if ("):
                return

        node_name = self.process_node_name(node_name)

        # 解析节点中的strings
        # 没有值，中止
        value_node = declarator_node.child_by_field_name('value')
        if not value_node:
            return

        # 没有string，中止

        must_compile_string_group, conditional_compile_string_groups = self.parse_node_strings_with_group(value_node)
        if not must_compile_string_group and not conditional_compile_string_groups:
            return
        numbers = self.parse_node_numbers(value_node)
        # 保存
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        normalized_hash = cal_normalized_hash(self.src_lines[start_line - 1:end_line])
        self.node_features.append(
            NodeFeature(node_name=node_name,
                        node_type=node_type,
                        start_line=start_line - 1,
                        end_line=end_line,
                        normalized_hash=normalized_hash,
                        must_compile_string_group=must_compile_string_group,
                        conditional_compile_string_groups=conditional_compile_string_groups,
                        numbers=numbers,
                        source_codes=self.src_lines[start_line - 1:end_line]))

    def parse_function_definition_node(self, node):
        body_node = node.child_by_field_name('body')
        if not body_node:
            return

        # 解析函数类型，名称
        identifier_node = node.child_by_field_name('declarator')
        node_type = identifier_node.type
        node_name = self.parse_node_content(identifier_node)[0]
        if node_type == "function_declarator" and node_name.startswith("if ("):
            return
        elif '\t' in node_name:
            return

        node_name = self.process_node_name(node_name)

        # 没有string，中止
        must_compile_string_group, conditional_compile_string_groups = self.parse_node_strings_with_group(body_node)
        numbers = self.parse_node_numbers(body_node)
        # 保存
        start_line = node.start_point[0] + 1
        end_line = node.end_point[0] + 1
        normalized_hash = cal_normalized_hash(self.src_lines[start_line - 1:end_line])
        self.node_features.append(
            NodeFeature(node_name=node_name,
                        node_type=node_type,
                        start_line=start_line - 1,
                        end_line=end_line,
                        normalized_hash=normalized_hash,
                        must_compile_string_group=must_compile_string_group,
                        conditional_compile_string_groups=conditional_compile_string_groups,
                        numbers=numbers,
                        source_codes=self.src_lines[start_line - 1:end_line]))

    def parse_node_content(self, node):
        """

        :param start_point: 起始点
        :param end_point: 结束点
        :return: List[str]
        """
        start_row, start_column = node.start_point
        end_row, end_column = node.end_point

        content_lines = []
        if start_row >= len(self.src_lines):
            return content_lines

        elif start_row == end_row:
            content_lines.append(self.src_lines[start_row][start_column:end_column])
        else:
            # 起始行
            content_lines.append(self.src_lines[start_row][start_column:])
            # 中间行
            content_lines.extend(self.src_lines[start_row + 1:end_row])
            # 结束行
            content_lines.append(self.src_lines[end_row][:end_column + 1])
        return content_lines

    def parse_node_tokens(self, root_node: Node):
        """
        获取所有的token
        返回：（node_type, node_content）
        :param root_node:
        :return:
        """
        token_list = []
        stack = deque([root_node])

        while stack:
            current_node = stack.pop()
            if current_node.children:
                stack.extend(reversed(current_node.children))
            else:
                if current_node.type != NodeType.comment.value:
                    tokens = [(current_node.type, content) for content in self.parse_node_content(current_node)]
                    token_list.extend(tokens)

        return token_list

    def parse_node_strings_with_group(self, node: Node):
        tokens = self.parse_node_tokens(node)
        # 必定编译组
        must_compile_group = []
        # 条件编译组 list
        conditional_compile_groups = []
        # 临时条件编译组
        tmp_compile_group = []
        # 是否是条件编译的flag
        conditional_compile_flag = 0
        # 是否需要和上一个字符串合并的flag
        last_token_is_string = False
        # 分组保存
        for token in tokens:
            node_type, node_content = token
            # 如果是个双引号，直接跳过
            if node_type == '"':
                continue

            # 如果是替换宏, 替换为字符串
            if node_content in self.replacement_macro_dict:
                node_type, node_content = NodeType.string_content.value, self.replacement_macro_dict[node_content]

            # 如果是字符串类型
            if node_type in {NodeType.string_content.value, NodeType.escape_sequence.value}:
                # print(node_type, node_content)
                # 根据编译标志选择要添加字符串的分组
                if conditional_compile_flag > 0:
                    current_group = tmp_compile_group
                else:
                    current_group = must_compile_group

                # 根据上一个字符串，确定如何添加
                # 如果上一个token 也是字符串，则需要合并
                if last_token_is_string:
                    current_group[-1] = current_group[-1] + node_content
                # 否则，直接添加
                else:
                    current_group.append(node_content)

                # 更改字符串标记
                last_token_is_string = True
            # 如果是宏类型，更新保存位置
            else:
                # 更改字符串标记
                last_token_is_string = False

                # 如果是条件编译宏
                if node_type in {"#if", "#ifdef", "#ifndef", "#elif", "#else", "#endif"}:
                    # 更新标志
                    if node_type in {"#if", "#ifdef", "#ifndef"}:
                        conditional_compile_flag += 1
                    elif node_type in {"#endif"}:
                        conditional_compile_flag -= 1

                    # 更换分组，保存临时结果
                    if tmp_compile_group:
                        conditional_compile_groups.append(tmp_compile_group)
                    tmp_compile_group = []

                    # 防止特殊情况减成负数
                    if conditional_compile_flag < 0:
                        conditional_compile_flag = 0

        # 最后的检查，防止漏掉
        if tmp_compile_group:
            conditional_compile_groups.append(tmp_compile_group)

        return must_compile_group, conditional_compile_groups

    def parse_node_numbers(self, node: Node):
        tokens = self.parse_node_tokens(node)
        numbers = []
        # 分组保存
        for token in tokens:
            node_type, node_content = token
            # print(node_type, node_content)
            if node_type in {"number_literal", "float_literal"}:
                numbers.append(node_content)
        return list(set(numbers))


def extract_file_feature(path):
    """
    这是个私有方法，因为被多进程调用，猜不用下划线开头，不要单独使用此函数
    :param path:
    :return:
    """
    file_feature_extractor = FileFeatureExtractor(path)
    try:
        file_feature_extractor.extract()
        return file_feature_extractor.result
    except Exception as e:
        logger.error(f'unexpected error occurred when extract_file_feature {path}, error: {e}')
        logger.error(traceback.format_exc())
        return None


class ProjectFeatureExtractor:
    ...

    def __init__(self, project_abs_path, progress_info=""):
        self.result: ProjectFeature

        self.project_abs_path = project_abs_path
        self.progress_info = progress_info
        self.target_file_paths = []
        self.filtered_target_file_paths = []
        self.file_feature_list: List[FileFeature] = []

    def extract(self, use_multiprocessing=False):
        logger.debug(f"{self.progress_info} extraction started.")
        start_at = time.perf_counter()
        # 找到文件
        self.__find_target_files()
        # 筛选文件
        self.__filter_and_sort_target_files()
        # 提取特征
        if use_multiprocessing:
            self.__extract_file_feature_multiple()
        else:
            self.__extract_file_feature()

        # 计算提交时间
        if CAL_COMMIT_TIME:
            self.cal_commit_time()

        # 生成最终结果
        self.result = ProjectFeature(
            self.project_abs_path,
            self.file_feature_list
        )

        # 简要总结
        logger.debug(
            f"{self.project_abs_path} extraction finished.\n"
            f"duration: {round(time.perf_counter() - start_at, 2)}s, "
            f"all_string_sum: {self.result.string_num}, "
            f"node_string_sum: {self.result.node_string_num}, "
            f"parse percent: {self.result.parse_percent}%")

    def __find_target_files(self):
        for root, dirs, files in os.walk(self.project_abs_path):
            for file in files:
                # check extensions
                if file.endswith(tuple(SUPPORTED_EXTENSION_SET)):
                    file_path = os.path.join(root, file)
                    if (
                            os.path.exists(file_path)
                            and os.path.isfile(file_path)
                            and not os.path.islink(file_path)
                            and calculate_file_md5(file_path)
                            != "0c7f234fe9a9e7e32a5f92047ca8a5c06b22cf29c9de4ae9c8a582b0616ace6c"  # empty file
                    ):
                        self.target_file_paths.append(file_path)

    def __filter_and_sort_target_files(self):
        """
        按照已知的一些文件夹名称先过滤一遍，主要是：third-party，dependencies，examples，demo

        :return:
        """
        filtered_file_path_size_tuple_list = []
        file_size_mb_sum = 0
        for file_path in self.target_file_paths:
            filter_flag = False
            for filter_dir_name in FILTER_DIR_NAME_SET:
                if len(filter_dir_name) <= 5:
                    filter_dir_name = f"/{filter_dir_name}/"
                if filter_dir_name in file_path:
                    filter_flag = True
                    break
            if filter_flag:
                continue

            file_size_bytes = os.path.getsize(file_path)
            file_size_mb = file_size_bytes / (1024 ** 2)

            # 过滤大于10M的文件,或者大于3m且名字中有test的文件
            if file_size_mb > 10:
                continue

            file_size_mb_sum += file_size_mb
            filtered_file_path_size_tuple_list.append((file_path, file_size_mb))

        if file_size_mb_sum > FEATURE_EXTRACTOR_MEMORY_LIMIT:
            raise MayOOMException(
                f"file size sum = {file_size_mb_sum}m > FEATURE_EXTRACTOR_MEMORY_LIMIT = {FEATURE_EXTRACTOR_MEMORY_LIMIT}")

        self.filtered_target_file_paths = [path for path, size in
                                           sorted(filtered_file_path_size_tuple_list, key=lambda x: x[1], reverse=True)]

    def __extract_file_feature_multiple(self):

        # 创建进程池，根据需要调整进程数
        num_processes = multiprocessing.cpu_count()  # 使用CPU核心数作为进程数
        pool = multiprocessing.Pool(processes=num_processes)

        # 使用map_async并行执行任务
        results = pool.map_async(extract_file_feature, self.filtered_target_file_paths)

        # 等待所有任务完成
        pool.close()
        pool.join()

        # 获取结果
        self.file_feature_list = [res for res in results.get() if res]

    def __extract_file_feature(self):
        # t = tqdm(self.filtered_target_file_paths, desc="extract_file_feature")
        for path in self.filtered_target_file_paths:
            # t.set_postfix({"processing:": self.progress_info})
            file_feature = extract_file_feature(path)
            if file_feature:
                self.file_feature_list.append(file_feature)

    def cal_commit_time(self):
        repo = git.Repo(self.project_abs_path)
        for file_feature in self.file_feature_list:
            # 计算每一行的提交时间
            file_path = file_feature.file_path
            try:
                blames = repo.blame('HEAD', file_path)
                line_commit_time_dict = dict()
                i = 0
                for blame in blames:
                    commit = blame[0]
                    lines = blame[1]
                    for _ in lines:
                        i += 1
                        line_commit_time_dict[i] = commit.committed_datetime

                # 补充最晚提交时间到node_feature中
                node_features = file_feature.node_features
                for node_feature in node_features:
                    start_line = node_feature.start_line
                    end_line = node_feature.end_line
                    latest_commit_time = line_commit_time_dict.get(start_line, None)
                    if not latest_commit_time:
                        logger.warning(f"get {file_path} {start_line} latest_commit_time failed.")
                        continue
                    for line_num in range(start_line, end_line + 1):
                        commit_time = line_commit_time_dict.get(line_num, None)  # 提交对象
                        if not commit_time:
                            logger.warning(f"get {file_path} {line_num} commit_time failed.")
                            continue

                        # 更新最晚提交时间
                        if commit_time > latest_commit_time:
                            latest_commit_time = commit_time
                    node_feature.commit_time = latest_commit_time
            except Exception as e:
                logger.error(f"unexpected error occurred when cal_commit_time {file_path}, error: {e} ")
                logger.error(traceback.format_exc())

    def dump(self, path):
        with open(path, 'w') as f:
            json.dump(self.result.custom_serialize(), f, ensure_ascii=False, indent=4)
