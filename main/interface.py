import dataclasses
import re
from dataclasses import dataclass
from enum import Enum
from typing import List

from loguru import logger

from bintools.general.bin_tool import normalize_asm_code
from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import remove_comments
from main.extractors.src_function_feature_extractor.entities import NodeFeature


@dataclass
class SrcFunctionFeature:
    """
    源代码函数特征
    """
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
    """
    二进制文件函数特征
    """
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
    """
    函数特征，包括源代码函数特征和二进制文件函数特征，以及函数名

    提取方法：同时提取源代码和二进制文件，并且找到同名的函数
    """
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


class SpecialToken(Enum):
    """
    一些特殊的token，用于标记一些特殊的信息
    """
    # for DataItemForFunctionConfirmModel
    SRC_CODE_SEPARATOR = "[SRC_CODE]"
    SRC_STRING_SEPARATOR = "[SRC_STR]"
    SRC_NUMBER_SEPARATOR = "[SRC_NUM]"
    ASM_CODE_SEPARATOR = "[ASM_CODE]"
    BIN_STRING_SEPARATOR = "[BIN_STR]"
    BIN_NUMBER_SEPARATOR = "[BIN_NUM]"

    # for normalizing assembly code
    ASM_REG = "<REG>"
    ASM_NUM = "<NUM>"
    ASM_JUMP = "<JUMP>"
    ASM_LOC = "<LOC>"
    ASM_MEM = "<MEM>"

    @classmethod
    def get_all_special_tokens(cls):
        return [token.value for token in cls]

    @classmethod
    def get_asm_special_tokens(cls):
        return [token.value for token in cls if token.name.startswith("ASM")]


class DataItemForFunctionConfirmModel:
    """
    训练数据项，用于函数确认模型
    """

    def __init__(self, function_name: str,
                 src_codes: List[str],
                 src_strings: List[str],
                 src_numbers: List,
                 asm_codes: List[str],
                 bin_strings: List[str],
                 bin_numbers: List,
                 bin_function_name="",
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
        self.bin_function_name = bin_function_name

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
            bin_function_name=function_feature.bin_function_feature.name,
            label=label
        )

    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_all_special_tokens()

    def get_train_text(self, separator=None):
        """
        生成text, 用于训练
        内容包括源代码、汇编代码、字符串、数字，以及特殊标记，主要用源码和汇编码的开头部分，以及字符串和数字
        :param separator:
        :return:
        """
        # 限制最多15行源代码
        src_code_text = remove_comments(" ".join(self.src_codes[:15]))

        # 过长过短的字符串不要,限制最多10个字符串，取长度最长的
        src_string_list = sorted(self.src_strings, key=lambda x: len(x), reverse=True)  #
        src_string_list = [string for string in src_string_list if 4 < len(string.split()) < 20][:10]
        src_strings = " ".join([self.function_name, *src_string_list])

        # 保留最长的10个数字
        src_numbers = " ".join(sorted([str(num) for num in self.src_numbers], key=lambda x: len(x), reverse=True)[:10])

        # 构成源码text
        src_text = f"{SpecialToken.SRC_CODE_SEPARATOR.value} {src_code_text}"
        if src_strings:
            src_text += f" {SpecialToken.SRC_STRING_SEPARATOR.value} {src_strings}"
        if src_numbers:
            src_text += f" {SpecialToken.SRC_NUMBER_SEPARATOR.value} {src_numbers}"

        # 限制最多20条汇编指令
        asm_code_text = " ".join(self.asm_codes[:20])

        # 限制最多10个字符串，取长度最长的
        bin_string_list = sorted(self.bin_strings, key=lambda x: len(x), reverse=True)[:10]
        bin_strings = " ".join(bin_string_list)

        # 保留最长的10个数字
        bin_numbers = " ".join(sorted([str(num) for num in self.bin_numbers], key=lambda x: len(x), reverse=True)[:10])

        # 构成汇编码text
        bin_text = f"{SpecialToken.SRC_CODE_SEPARATOR.value} {asm_code_text}"
        if bin_strings:
            bin_text += f" {SpecialToken.BIN_STRING_SEPARATOR.value} {bin_strings}"
        if bin_numbers:
            bin_text += f" {SpecialToken.BIN_NUMBER_SEPARATOR.value} {bin_numbers}"

        # 合并源码和汇编码
        if separator:
            merged_text = f"{src_text} {separator} {bin_text}"
        else:
            merged_text = f"{src_text} {bin_text}"
        return merged_text

    def normalize(self):
        # 正规化处理源代码
        self.src_codes = [normalized_line for line in self.src_codes
                          if (normalized_line := line.strip())]

        # 正规化处理字符串
        self.src_strings = [normalized_string for string in self.src_strings
                            if (normalized_string := string.strip())]

        # 正规化处理汇编代码
        self.asm_codes = [normalized_code for code in self.asm_codes
                          if (normalized_code := normalize_asm_code(code,
                                                                    reg_token=SpecialToken.ASM_REG.value,
                                                                    num_token=SpecialToken.ASM_NUM.value,
                                                                    jump_token=SpecialToken.ASM_JUMP.value,
                                                                    loc_token=SpecialToken.ASM_LOC.value,
                                                                    mem_token=SpecialToken.ASM_MEM.value))]
        # 正规化处理字符串
        self.bin_strings = [normalized_string for string in self.bin_strings
                            if (normalized_string := string.strip())]


@dataclass
class DataItemForCodeSnippetPositioningModel:
    """
    训练数据项，用于代码片段定位模型
    """

    def __init__(self, function_name: str,
                 src_codes: List[str],
                 asm_codes: List[str],
                 answer_start_index: int,
                 answer_end_index: int):
        self.function_name = function_name
        self.src_codes = src_codes
        self.asm_codes = asm_codes
        self.answer_start_index = answer_start_index
        self.answer_end_index = answer_end_index
        self.answer_asm_codes = self.asm_codes[self.answer_start_index:self.answer_end_index + 1]

        self.answer_length = len(self.asm_codes[self.answer_start_index:self.answer_end_index + 1])  # 结束位置的索引是闭区间
        self.src_length = len(self.src_codes)
        self.asm_length = len(self.asm_codes)

    def custom_serialize(self):
        return {
            "function_name": self.function_name,
            "src_length": self.src_length,
            "asm_length": self.asm_length,
            "answer_length": self.answer_length,
            "answer_start_index": self.answer_start_index,
            "answer_end_index": self.answer_end_index,
            "src_codes": self.src_codes,
            "asm_codes": self.asm_codes,
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            function_name=data['function_name'],
            src_codes=data['src_codes'],
            asm_codes=data['asm_codes'],
            answer_start_index=data['answer_start_index'],
            answer_end_index=data['answer_end_index'],
        )

    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_asm_special_tokens()

    def get_question_text(self):
        return remove_comments(" ".join(self.src_codes))

    def get_context_text(self):
        return " ".join(self.asm_codes)

    def get_answer_text(self):
        return " ".join(self.answer_asm_codes)

    def get_answer_position(self):
        # 这里要重新计算，换成字符的位置
        start_index = self.get_context_text().find(self.get_answer_text())
        end_index = start_index + len(self.get_answer_text()) - 1
        return start_index, end_index

    def normalize(self):
        normalized_src_codes = []
        for line in self.src_codes:
            if line.startswith(("+", "-")):
                continue
            if not (normalized_line := line.strip()):
                continue
            normalized_src_codes.append(normalized_line)
        self.src_codes = normalized_src_codes

        self.asm_codes = [normalized_code for code in self.asm_codes
                          if (normalized_code := self._normalize_asm_code(code))]

        self.answer_asm_codes = [normalized_code for code in self.answer_asm_codes
                                 if (normalized_code := self._normalize_asm_code(code))]

    def _normalize_asm_code(self, asm_code):
        # 如果输入的是原始的行信息，要先分割一下
        if "\t" in asm_code:
            asm_line_parts = asm_code.split("\t")
            if len(asm_line_parts) != 3:
                return None
            asm_code = asm_line_parts[-1]
        asm_code = normalize_asm_code(asm_code,
                                      reg_token=SpecialToken.ASM_REG.value,
                                      num_token=SpecialToken.ASM_NUM.value,
                                      jump_token=SpecialToken.ASM_JUMP.value,
                                      loc_token=SpecialToken.ASM_LOC.value,
                                      mem_token=SpecialToken.ASM_MEM.value)
        return asm_code


class DataItemForCodeSnippetConfirmModel:
    """
    训练数据项，用于代码片段确认模型
    """

    def __init__(self, src_codes: List[str],
                 asm_codes: List[str],
                 label=1):
        self.src_codes = src_codes
        self.asm_codes = asm_codes
        self.label = label

    def custom_serialize(self):
        return {
            "src_codes": self.src_codes,
            "asm_codes": self.asm_codes,
            "label": self.label
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            src_codes=data['src_codes'],
            asm_codes=data['asm_codes'],
            label=data['label']
        )

    def get_text(self, separator=None):
        src_text = remove_comments(" ".join(self.src_codes))
        asm_text = " ".join(self.asm_codes)
        return f"{src_text} {separator} {asm_text}" if separator else f"{src_text} {asm_text}"

    def get_label(self):
        return self.label

    def normalize(self):
        self.src_codes = [normalized_line for line in self.src_codes
                          if (normalized_line := line.strip())]

        self.asm_codes = [normalized_code for code in self.asm_codes
                          if (normalized_code := self._normalize_asm_code(code))]

    def _normalize_asm_code(self, asm_code):
        # 如果输入的是原始的行信息，要先分割一下
        if "\t" in asm_code:
            asm_line_parts = asm_code.split("\t")
            if len(asm_line_parts) != 3:
                return None
            asm_code = asm_line_parts[-1]
        asm_code = normalize_asm_code(asm_code,
                                      reg_token=SpecialToken.ASM_REG.value,
                                      num_token=SpecialToken.ASM_NUM.value,
                                      jump_token=SpecialToken.ASM_JUMP.value,
                                      loc_token=SpecialToken.ASM_LOC.value,
                                      mem_token=SpecialToken.ASM_MEM.value)
        return asm_code

    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_asm_special_tokens()


@dataclass
class Patch:
    """
    修复补丁信息
    """

    commit_link: str = ""
    commit_api: str = ""
    affected_since: str = ""
    fixed_in: str = ""

    start_line_before_commit: int = 0
    snippet_size_before_commit: int = 0
    snippet_codes_before_commit: List[str] = dataclasses.field(default_factory=list)
    snippet_codes_text_before_commit: str = ""

    start_line_after_commit: int = 0
    snippet_size_after_commit: int = 0
    snippet_codes_after_commit: List[str] = dataclasses.field(default_factory=list)
    snippet_codes_text_after_commit: str = ""

    def customer_serialize(self):
        return {
            "commit_link": self.commit_link,
            "commit_api": self.commit_api,
            "affected_since": self.affected_since,
            "fixed_in": self.fixed_in,
            "start_line_before_commit": self.start_line_before_commit,
            "end_line_before_commit": self.snippet_size_before_commit,
            "snippet_codes_before_commit": self.snippet_codes_before_commit,
            "start_line_after_commit": self.start_line_after_commit,
            "end_line_after_commit": self.snippet_size_after_commit,
            "snippet_codes_after_commit": self.snippet_codes_after_commit,

        }


@dataclass
class CauseFunction:
    """
    漏洞函数
    NOTE:
        1. file_path: 源代码文件实际存储路径, 例如: "TestCases/model_train/model_1/test_data/p12_add.c", 不是文件相对项目的路径
    """

    file_path: str
    function_name: str

    project_name: str = ""
    line_start: int = 0
    line_end: int = 0
    normalized_src_codes: List[str] = dataclasses.field(default_factory=list)

    def customer_serialize(self):
        return {
            "project_name": self.project_name,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "normalized_src_codes": self.normalized_src_codes,
        }


@dataclass
class Vulnerability:
    """
    漏洞信息
    """
    cve_id: str
    cve_link: str
    title: str = ""
    severity: str = ""
    description: str = ""
    cause_function: CauseFunction = None
    patches: List[Patch] = dataclasses.field(default_factory=list)

    def customer_serialize(self):
        return {
            "cve_id": self.cve_id,
            "cve_link": self.cve_link,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "cause_function": self.cause_function.customer_serialize(),
            "patches": [patch.customer_serialize() for patch in self.patches]
        }


@dataclass
class PossibleBinFunction:
    """
    可能与漏洞函数相关的二进制文件函数
    """
    function_name: str
    match_possibility: float
    asm_codes: List[str] = dataclasses.field(default_factory=list)
    asm_codes_window_texts: List[str] = dataclasses.field(default_factory=list)
    predictions: List = dataclasses.field(default_factory=list)

    conclusion: bool = False
    judge_reason: str = ""

    def customer_serialize(self):
        return {
            "function_name": self.function_name,
            "match_possibility": self.match_possibility,
            "conclusion": self.conclusion,
            "judge_reason": self.judge_reason,
            "asm_codes": self.asm_codes,
            "asm_codes_window_texts": self.asm_codes_window_texts,
            "predictions": [[pred.item(), prob.item()] for pred, prob in self.predictions]
        }


@dataclass
class ConfirmAnalysis:
    # bin file path
    # input

    vulnerability: Vulnerability
    possible_bin_functions: List[PossibleBinFunction] = dataclasses.field(default_factory=list)
    conclusion: bool = False
    def customer_serialize(self):
        return {
            "conclusion": self.conclusion,
            "vulnerability": self.vulnerability.customer_serialize(),
            "possible_bin_functions": [possible_bin_function.customer_serialize()
                                       for possible_bin_function in self.possible_bin_functions]
        }
