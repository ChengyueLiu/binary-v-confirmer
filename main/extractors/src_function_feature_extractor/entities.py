#!/usr/bin/env python
# -*- coding: utf-8 -*-


# @Time : 2023/9/25 11:51
# @Author : Liu Chengyue
# @File : entities.py
# @Software: PyCharm

import enum
import os.path
from datetime import datetime
from typing import List

from loguru import logger

from bintools.general.file_tool import calculate_file_md5


class MayOOMException(Exception):
    pass


class NodeFeature:
    def __init__(self, node_name, node_type, start_line, end_line, normalized_hash, must_compile_string_group,
                 conditional_compile_string_groups,
                 numbers,
                 source_codes: List[str]):
        self.name = node_name
        self.type = node_type
        self.start_line = start_line
        self.end_line = end_line
        self.numbers = numbers
        self.normalized_hash = normalized_hash
        self.commit_time: datetime = None
        self.must_compile_string_group: List[str] = must_compile_string_group
        self.conditional_compile_string_groups: List[List[str]] = conditional_compile_string_groups
        self.source_codes: List[str] = source_codes

    def custom_serialize(self):
        if self.must_compile_string_group or self.conditional_compile_string_groups:
            json_data = {
                "name": self.name,
                "type": self.type,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "normalized_hash": self.normalized_hash,
                "commit_time": self.commit_time.strftime('%Y-%m-%d %H:%M:%S') if self.commit_time else None,
                "source_codes": self.source_codes,
                "numbers": self.numbers,
                "strings": {
                    "must_compile_string_group": self.must_compile_string_group,
                    "conditional_compile_string_groups": self.conditional_compile_string_groups
                }
            }
        else:
            json_data = {
                "name": self.name,
                "type": self.type,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "normalized_hash": self.normalized_hash,
                "commit_time": self.commit_time.strftime('%Y-%m-%d %H:%M:%S') if self.commit_time else None,
                "numbers": self.numbers,
                "source_codes": self.source_codes,
            }
        return json_data


class FileFeature:
    def __init__(self,
                 # basic info
                 file_path,
                 can_decode,

                 # features
                 parse_error_line_numer_set,
                 all_strings,
                 node_features: List[NodeFeature],

                 # statistics
                 line_num

                 ):
        node_features = sorted(node_features, key=lambda x: x.start_line)
        # basic info
        self.file_path = file_path
        self.can_decode = can_decode
        self.file_name = os.path.basename(file_path)
        if os.path.exists(file_path):
            self.file_size = os.path.getsize(file_path)
            self.file_md5 = calculate_file_md5(file_path)
        else:
            self.file_size = None
            self.file_md5 = None

        # features
        self.parse_error_line_number_list = list(parse_error_line_numer_set)
        # 合并节点字符串
        self.node_strings = [
            *[s
              for node_feature in node_features
              for s in node_feature.must_compile_string_group],
            *[s
              for node_feature in node_features
              for g in node_feature.conditional_compile_string_groups
              for s in g]
        ]
        # 计算节点字符串与所有字符串之间的差异
        self.string_num_difference = len([s for s in set(all_strings) - set(self.node_strings) if s != 'C'])

        # 如果有错误行，且差异过大，日志提醒
        if self.parse_error_line_number_list and self.string_num_difference > 30:
            logger.debug(
                f"{self.file_path} may path failed. the difference between all string num and node string num is {self.string_num_difference}")

        self.all_strings = all_strings
        self.node_features: List[NodeFeature] = node_features

        # statistics
        self.line_num = line_num
        self.node_num = len(node_features)
        self.node_with_strings_num = len(
            [nf for nf in node_features if nf.must_compile_string_group or nf.conditional_compile_string_groups])
        self.string_num = len(all_strings)
        self.unique_string_num = len(set(all_strings))
        self.node_string_num = len(self.node_strings)
        self.unique_node_string_num = len(set(self.node_strings))
        self.parse_percent = round((self.node_string_num / self.string_num) * 100, 4) if self.string_num != 0 else 100.0

    def custom_serialize(self):
        json_data = {
            "file_path": self.file_path,
            "can_decode": self.can_decode,
            "file_name": self.file_name,
            "file_size": self.file_size,
            "file_md5": self.file_md5,
            "statistics": {
                "line_num": self.line_num,
                "node_num": self.node_num,
                "node_with_strings_num": self.node_with_strings_num,
                "string_num": self.string_num,
                "unique_string_num": self.unique_string_num,
                "node_string_num": self.node_string_num,
                "unique_node_string_num": self.unique_string_num,
                "parse_percent": self.parse_percent
            },
            "parse_error_line_numer_list": self.parse_error_line_number_list,
            "node_features": [nf.custom_serialize() for nf in self.node_features],
            "all_strings": self.all_strings,
        }
        return json_data


class ProjectFeature:
    def __init__(self, project_path, file_features: List[FileFeature]):
        # basic info
        self.project_name: str = os.path.basename(project_path)

        # features
        # 这里把文件路径替换成相对路径
        for ff in file_features:
            ff.file_path = os.path.relpath(ff.file_path, project_path)
        self.file_features: List[FileFeature] = file_features

        # statistics
        self.file_num = len(file_features)
        self.line_num = sum(ff.line_num for ff in file_features)
        self.node_num = sum(ff.node_num for ff in file_features)
        self.node_with_strings_num = sum(ff.node_with_strings_num for ff in file_features)

        self.string_num = sum(ff.string_num for ff in file_features)
        all_strings_set = set(s for ff in file_features for s in ff.all_strings)
        self.unique_string_num = len(all_strings_set)

        self.node_string_num = sum(ff.node_string_num for ff in file_features)
        node_strings_set = set(s for ff in file_features for s in ff.node_strings)
        self.unique_string_num = len(node_strings_set)

        self.parse_percent = round((self.node_string_num / self.string_num) * 100, 4) if self.string_num != 0 else 1

    def custom_serialize(self):
        json_data = {
            "repository_name": self.project_name,
            "statistics": {
                "file_num": self.file_num,
                "line_num": self.line_num,
                "node_num": self.node_num,
                "node_with_strings_num": self.node_with_strings_num,
                "string_num": self.string_num,
                "unique_string_num": self.unique_string_num,
                "node_string_num": self.node_string_num,
                "unique_node_string_num": self.unique_string_num,
                "parse_percent": self.parse_percent
            },
            "file_features": [ff.custom_serialize() for ff in self.file_features],
        }
        return json_data


class NodeType(enum.Enum):
    # 识别错误
    error = "ERROR"

    function_declarator = "function_declarator"  # 函数声明
    function_definition = "function_definition"  # 函数定义
    pointer_declarator = "pointer_declarator"  # 指针声明
    string_literal = 'string_literal'  # 字符串节点
    string_content = 'string_content'  # 字符串内容
    escape_sequence = 'escape_sequence'  # 字符串内容
    preproc_include = 'preproc_include'  # 头文件
    comment = 'comment'  # 注释
    declaration = 'declaration'  # 变量声明
    initializer_list = 'initializer_list'  # 初始化列表
    preproc_def = 'preproc_def'  # 替换宏 #define AAA aaa, 或者普通定义 #define AAA
    extern = 'extern'  # 替换宏 #define AAA aaa, 或者普通定义 #define AAA

    # 六种常见的条件编译宏
    m_if = "#if"
    m_ifdef = "#ifdef"
    m_ifndef = "#ifndef"
    m_elif = "#elif"
    m_else = "#else"
    m_endif = "#endif"


class Version:
    def __init__(self, version_info):
        self.library_id = version_info['library_id']
        self.library_name = version_info['library_name']
        self.version_id = version_info['version_id']
        self.version_number = version_info['version_number']
        self.version_type = version_info['version_type']
        self.tagged_date = version_info['tagged_date']
        self.commit_date = version_info['commit_date']
        self.commit_hash = version_info['commit_hash']
