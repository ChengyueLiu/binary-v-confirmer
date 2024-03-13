import re
from dataclasses import dataclass
from typing import List

from loguru import logger

from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import remove_comments
from main.extractors.src_function_feature_extractor.entities import NodeFeature


@dataclass
class SrcFunctionFeature:
    name: str
    file_path: str
    line_start: int
    line_end: int
    original_lines: List[str]
    strings: List[str]
    numbers: List[int]
    hash_value: str

    @classmethod
    def init_from_node_feature(cls, file_path, node_feature: NodeFeature):
        """
        从NodeFeature对象初始化SrcFunctionFeature对象
        :param file_path:
        :param node_feature:
        :return:
        """
        function_strings = []
        function_strings.extend(node_feature.must_compile_string_group)
        for string_group in node_feature.conditional_compile_string_groups:
            function_strings.extend(string_group)
        src_function_feature = SrcFunctionFeature(
            name=node_feature.name,
            file_path=file_path,
            line_start=node_feature.start_line,
            line_end=node_feature.end_line,
            original_lines=[line.rstrip() for line in node_feature.source_codes],
            strings=function_strings,
            numbers=node_feature.numbers,
            hash_value=node_feature.normalized_hash
        )
        return src_function_feature

    @classmethod
    def init_from_dict(cls, data: dict):
        """
        从字典初始化SrcFunctionFeature对象
        :param data:
        :return:
        """
        return cls(
            name=data['name'],
            file_path=data['file_path'],
            line_start=data['line_start'],
            line_end=data['line_end'],
            original_lines=data['original_lines'],
            strings=data['strings'],
            numbers=data['numbers'],
            hash_value=data['hash_value']
        )

    @classmethod
    def init_from_json_file(cls, file_path: str):
        """
        从json文件初始化SrcFunctionFeature对象
        :param file_path:
        :return:
        """
        data = load_from_json_file(file_path)
        return [cls.init_from_dict(item) for item in data]

    def custom_serialize(self):
        return {
            "name": self.name,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "original_lines": self.original_lines,
            "strings": self.strings,
            "numbers": self.numbers,
            "hash_value": self.hash_value
        }


@dataclass
class BinFunctionFeature:
    name: str
    asm_codes: List[str]
    strings: List[str]
    numbers: List[int]

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            name=data['name'],
            asm_codes=data['asm_codes'],
            strings=data['strings'],
            numbers=data['numbers']
        )

    @classmethod
    def init_from_json_file(cls, file_path: str):
        data = load_from_json_file(file_path)
        return [cls.init_from_dict(item) for item in data]

    def custom_serialize(self):
        return {
            "name": self.name,
            "asm_codes": self.asm_codes,
            "strings": self.strings,
            "numbers": self.numbers
        }


@dataclass
class FunctionFeature:
    function_name: str
    bin_function_feature: BinFunctionFeature
    src_function_features: List[SrcFunctionFeature]

    def custom_serialize(self):
        return {
            "function_name": self.function_name,
            "src_function_features": [sff.custom_serialize() for sff in self.src_function_features],
            "bin_function_feature": self.bin_function_feature.custom_serialize()
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            function_name=data['function_name'],
            bin_function_feature=BinFunctionFeature.init_from_dict(data['bin_function_feature']),
            src_function_features=[SrcFunctionFeature.init_from_dict(item) for item in data['src_function_features']]
        )

    @classmethod
    def init_from_json_file(cls, function_feature_path):
        data = load_from_json_file(function_feature_path)
        return [cls.init_from_dict(item) for item in data]


class DataItemForFunctionConfirmModel:
    src_code_separator = "[SRC_CODE]"
    src_string_separator = "[SRC_STR]"
    src_number_separator = "[SRC_NUM]"
    asm_code_separator = "[ASM_CODE]"
    bin_string_separator = "[BIN_STR]"
    bin_number_separator = "[BIN_NUM]"

    # asm special tokens
    asm_reg = "<REG>"
    asm_num = "<NUM>"
    jump_label = "<JUMP>"
    loc_label = "<LOC>"

    def __init__(self, function_name: str,
                 src_codes: List[str],
                 src_strings: List[str],
                 src_numbers: List,
                 asm_codes: List[str],
                 bin_strings: List[str],
                 bin_numbers: List,
                 label=1):
        """
        从原始特征中初始化训练数据
        :param function_feature:
        """
        self.function_name = function_name
        self.src_codes: List[str] = src_codes
        self.src_strings: List[str] = src_strings
        self.src_numbers: List[str] = [str(num) for num in src_numbers]
        self.asm_codes: List[str] = asm_codes
        self.bin_strings: List[str] = bin_strings
        self.bin_numbers: List[str] = [str(num) for num in bin_numbers]
        self.label = label

        self._normalize()

    def custom_serialize(self):
        return {
            "function_name": self.function_name,
            "src_codes": self.src_codes,
            "src_strings": self.src_strings,
            "src_numbers": self.src_numbers,
            "asm_codes": self.asm_codes,
            "bin_strings": self.bin_strings,
            "bin_numbers": self.bin_numbers,
            "label": self.label
        }

    @classmethod
    def init_from_dict(cls, json_data_item):
        return cls(
            json_data_item['function_name'],
            json_data_item['src_codes'],
            json_data_item['src_strings'],
            json_data_item['src_numbers'],
            json_data_item['asm_codes'],
            json_data_item['bin_strings'],
            json_data_item['bin_numbers'],
            label=json_data_item['label']
        )

    @classmethod
    def init_from_function_feature(cls, function_feature: FunctionFeature, label=1):
        return cls(
            function_feature.function_name,
            function_feature.src_function_features[0].original_lines,
            function_feature.src_function_features[0].strings,
            function_feature.src_function_features[0].numbers,
            function_feature.bin_function_feature.asm_codes,
            function_feature.bin_function_feature.strings,
            function_feature.bin_function_feature.numbers,
            label=label
        )

    @classmethod
    def get_special_tokens(cls):
        return [cls.src_code_separator,
                cls.src_string_separator,
                cls.src_number_separator,
                cls.asm_code_separator,
                cls.bin_string_separator,
                cls.bin_number_separator,
                cls.asm_reg,
                cls.asm_num,
                cls.jump_label,
                cls.loc_label]

    def get_train_text(self, separator=None):
        """
        生成text, 用于训练
        内容包括源代码、汇编代码、字符串、数字，以及特殊标记，主要用源码和汇编码的开头部分，以及字符串和数字
        :param separator:
        :return:
        """
        src_code_text = remove_comments(" ".join(self.src_codes[:15]))  # 限制最多15行源代码
        src_string_list = sorted(self.src_strings, key=lambda x: len(x), reverse=True)  #
        src_string_list = [string for string in src_string_list if 4 < len(string.split()) < 20][
                          :10]  # 过长过短的字符串不要,限制最多10个字符串，取长度最长的
        src_strings = " ".join([self.function_name, *src_string_list])
        src_numbers = " ".join(
            sorted([str(num) for num in self.src_numbers], key=lambda x: len(x), reverse=True)[:10])  # 保留最长的10个数字
        src_text = f"{self.src_code_separator} {src_code_text}"
        if src_strings:
            src_text += f" {self.src_string_separator} {src_strings}"
        if src_numbers:
            src_text += f" {self.src_number_separator} {src_numbers}"

        asm_code_text = " ".join(self.asm_codes[:20])  # 限制最多20条汇编指令
        bin_string_list = sorted(self.bin_strings, key=lambda x: len(x), reverse=True)[:10]  # 限制最多10个字符串，取长度最长的
        bin_strings = " ".join(bin_string_list)
        bin_numbers = " ".join(sorted([str(num) for num in self.bin_numbers], key=lambda x: len(x), reverse=True)[:10])
        bin_text = f"{self.asm_code_separator} {asm_code_text}"
        if bin_strings:
            bin_text += f" {self.bin_string_separator} {bin_strings}"
        if bin_numbers:
            bin_text += f" {self.bin_number_separator} {bin_numbers}"
        if separator:
            merged_text = f"{src_text} {separator} {bin_text}"
        else:
            merged_text = f"{src_text} {bin_text}"
        return merged_text

    def _normalize(self):
        # 正规化处理源代码
        self.src_codes = [normalized_line for line in self.src_codes
                          if (normalized_line := self._normalize_src_code(line))]

        # 正规化处理字符串
        self.src_strings = [normalized_string for string in self.src_strings
                            if (normalized_string := self._normalize_src_string(string))]
        # 正规化处理数字
        self.src_numbers = [normalized_number for number in self.src_numbers
                            if (normalized_number := self._normalize_src_number(number))]

        # 正规化处理汇编代码
        self.asm_codes = [normalized_code for code in self.asm_codes
                          if (normalized_code := self._normalize_bin_code(code))]
        # 正规化处理字符串
        self.bin_strings = [normalized_string for string in self.bin_strings
                            if (normalized_string := self._normalize_bin_string(string))]
        # 正规化处理数字
        self.bin_numbers = [normalized_number for number in self.bin_numbers
                            if (normalized_number := self._normalize_bin_number(number))]

    def _normalize_src_code(self, src_code: str):
        # 正规化处理源代码
        return src_code.strip()

    def _normalize_src_string(self, src_string: str):
        return src_string

    def _normalize_src_number(self, src_number: str):
        # 正规化处理数字
        return src_number

    def _normalize_bin_code(self, asm_code: str):
        # 正规化处理汇编代码
        # 替换连续的空格为单个空格
        asm_code = re.sub(r"\s+", " ", asm_code).strip()
        # 移除注释
        asm_code = re.sub(r";.*", "", asm_code)
        # 替换寄存器和立即数
        asm_code = re.sub(r"\br[\w\d]+\b", self.asm_reg, asm_code)
        asm_code = re.sub(r"\b\d+\b", self.asm_num, asm_code)
        # 简化控制流指令
        asm_code = re.sub(r"\bj(mp|e|z|nz|ne|g|ge|l|le)\b", self.jump_label, asm_code)
        # 简化跳转标签和地址
        asm_code = re.sub(r"\bloc(ret)?_[\w\d]+\b", self.loc_label, asm_code)
        return asm_code

    def _normalize_bin_string(self, bin_string: str):
        # 正规化处理字符串
        return bin_string

    def _normalize_bin_number(self, bin_number: str):
        # 正规化处理数字
        return bin_number


@dataclass
class DataItemForCodeSnippetPositioningModel:
    src_code_snippet: List[str]
    asm_code_snippet: List[str]
    asm_code_snippet_context: List[str]

    def custom_serialize(self):
        return {
            "src_code_snippet": self.src_code_snippet,
            "asm_code_snippet": self.asm_code_snippet,
            "asm_code_snippet_context": self.asm_code_snippet_context
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            src_code_snippet=data['src_code_snippet'],
            asm_code_snippet=data['asm_code_snippet'],
            asm_code_snippet_context=data['asm_code_snippet_context']
        )

    def normalize(self):
        pass
