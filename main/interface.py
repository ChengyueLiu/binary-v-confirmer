import dataclasses
import os
import random
from dataclasses import dataclass, fields, asdict
from enum import Enum
from typing import List, Type, Dict, Any

from bintools.general.file_tool import load_from_json_file
from bintools.general.normalize import normalize_asm_lines, normalize_asm_code, normalize_src_lines, remove_comments, \
    normalize_strings
from bintools.general.src_tool import count_function_effective_lines
from main.extractors.src_function_feature_extractor.entities import NodeFeature


@dataclass
class Serializable:
    def customer_serialize(self) -> Dict[str, Any]:
        # 使用 asdict 来序列化所有实例属性，包括那些带默认值的
        serialized_data = asdict(self)
        # 额外处理复杂类型，例如含有 customer_serialize 方法的属性
        for field in fields(self):
            value = getattr(self, field.name)
            if hasattr(value, 'customer_serialize'):
                serialized_data[field.name] = value.customer_serialize()
            elif isinstance(value, list) and value and hasattr(value[0], 'customer_serialize'):
                serialized_data[field.name] = [item.customer_serialize() for item in value]
        return serialized_data

    @classmethod
    def init_from_dict(cls: Type['Serializable'], data: Dict[str, Any]) -> 'Serializable':
        init_args = {}
        for field in fields(cls):
            field_value = data.get(field.name)
            if hasattr(field.type, 'init_from_dict') and isinstance(field_value, dict):
                init_args[field.name] = field.type.init_from_dict(field_value)
            elif (isinstance(field_value, list) and
                  field.type.__args__ and
                  hasattr(field.type.__args__[0], 'init_from_dict') and
                  all(isinstance(i, dict) for i in field_value)):
                init_args[field.name] = [field.type.__args__[0].init_from_dict(item) for item in field_value]
            else:
                init_args[field.name] = field_value
        return cls(**init_args)


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
    def batch_init_from_json_file(cls, file_path: str):
        """
        从json文件初始化SrcFunctionFeature对象
        :param file_path:
        :return:
        """
        data = load_from_json_file(file_path)
        return [cls.init_from_dict(item) for item in data]

    @classmethod
    def init_from_json_file(cls, file_path: str):
        """
        从json文件初始化SrcFunctionFeature对象
        :param file_path:
        :return:
        """
        data = load_from_json_file(file_path)
        return cls.init_from_dict(data)

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

    # frequent asm tokens

    @classmethod
    def get_all_special_tokens(cls):
        return [token.value for token in cls]

    @classmethod
    def get_asm_special_tokens(cls):
        return [token.value for token in cls if token.name.startswith("ASM")]

    @classmethod
    def get_asm_frequent_tokens(cls):
        frequent_tokens = ['mov', '<MEM>', 'rax', 'eax', '<JUMP>', '<LOC>', 'rdx', 'call', 'edx', 'rdi', '0x0',
                           'cmp', 'lea', 'edi', 'add', 'esi', '', '[ASM_CODE]', 'test', 'rsi', 'ecx', 'rcx', '00',
                           '0x1', 'and', 'shl', 'al', 'sub', 'movsxd', 'movzx', '0x2', 'or', 'rsp']

        return frequent_tokens


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
                 label=1,
                 similarity=0):
        """
        从原始特征中初始化训练数据
        :param function_feature:
        """
        self.id = 0
        self.function_name = function_name
        self.src_codes: List[str] = src_codes
        self.src_strings: List[str] = src_strings
        self.src_numbers: List[str] = [str(num) for num in src_numbers]
        self.asm_codes: List[str] = asm_codes
        self.bin_strings: List[str] = bin_strings
        self.bin_numbers: List[str] = [str(num) for num in bin_numbers]
        self.label = label
        self.bin_function_name = bin_function_name

        self.similarity = similarity
        self.is_normalized = False

    def custom_serialize(self):
        return {
            "id": self.id,
            "label": self.label,
            "similarity": self.similarity,
            "function_name": self.function_name,
            "src_codes": self.src_codes,
            "src_strings": self.src_strings,
            "src_numbers": self.src_numbers,
            "asm_codes": self.asm_codes,
            "bin_strings": self.bin_strings,
            "bin_numbers": self.bin_numbers,
        }

    @classmethod
    def init_from_dict(cls, json_data_item):
        obj = cls(
            json_data_item['function_name'],
            json_data_item['src_codes'],
            json_data_item['src_strings'],
            json_data_item['src_numbers'],
            json_data_item['asm_codes'],
            json_data_item['bin_strings'],
            json_data_item['bin_numbers'],
            label=json_data_item['label'],
            similarity=json_data_item.get('similarity', 0)
        )
        obj.id = json_data_item.get('id', 0)
        return obj

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

    def get_train_text(self, separator):
        """
        生成text, 用于训练
        源代码行数和汇编代码行数大概是 3.5
        :param separator:
        :return:
        """
        src_line_num = 1
        asm_line_num = 3
        text = f"{SpecialToken.SRC_CODE_SEPARATOR.value} {' '.join(self.src_codes[:src_line_num])} {separator} {SpecialToken.ASM_CODE_SEPARATOR.value} {' '.join(self.asm_codes[:asm_line_num])}"
        ratio = round(len(self.asm_codes) / len(self.src_codes))
        while src_line_num <= len(self.src_codes) and asm_line_num <= len(self.asm_codes):
            src_line_num += 1
            current_src_line = self.src_codes[:src_line_num][-1]
            if len(current_src_line) == 1 or current_src_line == '"STR"':
                src_line_num += 1
            asm_line_num += ratio
            text = f" {SpecialToken.SRC_CODE_SEPARATOR.value} {' '.join(self.src_codes[:src_line_num])} {separator} {SpecialToken.ASM_CODE_SEPARATOR.value} {' '.join(self.asm_codes[:asm_line_num])}"
            if len(text) > 1000:
                break
        return text

    def normalize(self):
        if self.is_normalized:
            return

        # 正规化处理源代码
        self.src_codes = normalize_src_lines(self.src_codes)

        # 正规化处理字符串
        self.src_strings = normalize_strings(self.src_strings)

        # 正规化处理汇编代码
        self.asm_codes = normalize_asm_lines(self.asm_codes)

        # 正规化处理字符串
        self.bin_strings = normalize_strings(self.bin_strings)

        self.is_normalized = True


@dataclass
class DataItemForCodeSnippetPositioningModel:
    """
    训练数据项，用于代码片段定位模型
    """

    def __init__(self, function_name: str,
                 src_codes: List[str],
                 asm_codes: List[str],
                 answer_asm_codes: List[str] = None):
        self.id = 0
        self.function_name = function_name
        self.src_codes = src_codes
        self.asm_codes = asm_codes
        if answer_asm_codes is None:
            self.answer_asm_codes = []
        else:
            self.answer_asm_codes = answer_asm_codes

        self.src_length = len(self.src_codes)
        self.effective_src_length = count_function_effective_lines(self.src_codes)
        self.asm_length = len(self.asm_codes)
        self.answer_length = len(self.answer_asm_codes)

    def custom_serialize(self):
        return {
            "id": self.id,
            "function_name": self.function_name,
            "src_length": self.src_length,
            "effective_src_length": self.effective_src_length,
            "asm_length": self.asm_length,
            "answer_length": self.answer_length,
            "src_codes": self.src_codes,
            "asm_codes": self.asm_codes,
            "answer_asm_codes": self.answer_asm_codes,
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        obj = cls(
            function_name=data['function_name'],
            src_codes=data['src_codes'],
            asm_codes=data['asm_codes'],
            answer_asm_codes=data['answer_asm_codes']
        )
        obj.id = data.get('id', 0)
        return obj

    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_asm_special_tokens()

    def get_question_text(self):
        return " ".join(self.src_codes)

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
        # 正规化处理源代码
        lines = []
        for line in self.src_codes:
            if line.startswith(("+", "-")):
                line = line[1:]
            lines.append(line.strip())
        self.src_codes = normalize_src_lines(lines)

        # 正规化处理汇编代码
        self.asm_codes = normalize_asm_lines(self.asm_codes)

        self.answer_asm_codes = normalize_asm_lines(self.answer_asm_codes)


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
                          if (normalized_code := normalize_asm_code(code,
                                                                    reg_token=SpecialToken.ASM_REG.value,
                                                                    num_token=SpecialToken.ASM_NUM.value,
                                                                    jump_token=SpecialToken.ASM_JUMP.value,
                                                                    loc_token=SpecialToken.ASM_LOC.value,
                                                                    mem_token=SpecialToken.ASM_MEM.value))]

    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_asm_special_tokens()


@dataclass
class DataItemForCodeSnippetConfirmModelMC(Serializable):
    """
    训练数据项，用于代码片段确认模型
    """
    function_name: str
    choice_index: int
    wrong_type: int
    asm_codes: List[str]
    src_codes_0: List[str]
    src_codes_1: List[str]

    def __init__(self,
                 function_name: str,
                 asm_codes: List[str],
                 src_codes_0: List[str],
                 src_codes_1: List[str],
                 choice_index=0,
                 wrong_type=1):
        self.function_name = function_name
        self.choice_index = choice_index
        self.wrong_type = wrong_type
        self.asm_codes = asm_codes
        self.src_codes_0 = src_codes_0
        self.src_codes_1 = src_codes_1


    @classmethod
    def get_special_tokens(cls):
        return SpecialToken.get_asm_special_tokens()

    def get_question_text(self):
        # 限制最多50行汇编代码
        return " ".join(self.asm_codes[:50])

    def get_src_codes_0_text(self):
        return remove_comments(" ".join(self.src_codes_0))

    def get_src_codes_1_text(self):
        return remove_comments(" ".join(self.src_codes_1))

    def get_choice_index(self):
        return self.choice_index

    def normalize(self):
        self.src_codes_0 = normalize_src_lines(self.src_codes_0)
        self.src_codes_1 = normalize_src_lines(self.src_codes_1)
        self.asm_codes = normalize_asm_lines(self.asm_codes)

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
            "before_commit": {
                "start_line": self.start_line_before_commit,
                "snippet_size": self.snippet_size_before_commit,
                "snippet_codes": self.snippet_codes_before_commit,
                "snippet_codes_text": self.snippet_codes_text_before_commit
            },
            "after_commit": {
                "start_line": self.start_line_after_commit,
                "snippet_size": self.snippet_size_after_commit,
                "snippet_codes": self.snippet_codes_after_commit,
                "snippet_codes_text": self.snippet_codes_text_after_commit
            }
        }


@dataclass
class PossibleAsmSnippet:
    src_codes_text: str
    asm_codes_text: str
    match_type: int
    probability: float
    scores: List[float]

    def customer_serialize(self):
        return {
            "src_codes_text": self.src_codes_text,
            "asm_codes_text": self.asm_codes_text,
            "match_type": self.match_type,
            "probability": self.probability,
            "scores": [float(score) for score in self.scores]
        }


@dataclass
class PossibleBinFunction:
    """
    可能与漏洞函数相关的二进制文件函数
    """
    function_name: str
    match_possibility: float
    asm_codes: List[str] = dataclasses.field(default_factory=list)
    possible_vul_snippets: List[PossibleAsmSnippet] = dataclasses.field(default_factory=list)
    confirmed_vul_snippet_count: int = 0
    vul_score: float = 0.0

    possible_patch_snippets: List[PossibleAsmSnippet] = dataclasses.field(default_factory=list)
    confirmed_patch_snippet_count: int = 0
    patch_score: float = 0.0

    has_vul_snippet: bool = False
    has_patch_snippet: bool = False

    is_vul_function: bool = False
    is_repaired: bool = False
    judge_reason: str = ""

    def customer_serialize(self):
        return {
            "function_name": self.function_name,
            "match_possibility": self.match_possibility,
            "has_vul_snippet": self.has_vul_snippet,
            "confirmed_vul_snippet_count": self.confirmed_vul_snippet_count,
            "vul_score": self.vul_score,
            "has_patch_snippet": self.has_patch_snippet,
            "confirmed_patch_snippet_count": self.confirmed_patch_snippet_count,
            "patch_score": self.patch_score,
            "is_vul_function": self.is_vul_function,
            "is_repaired": self.is_repaired,
            "judge_reason": self.judge_reason,

            "asm_codes": self.asm_codes,
            "possible_vul_snippets": [possible_vul_snippet.customer_serialize() for possible_vul_snippet in
                                      self.possible_vul_snippets],
            "possible_patch_snippets": [possible_patch_snippet.customer_serialize() for possible_patch_snippet in
                                        self.possible_patch_snippets]
        }


@dataclass
class CauseFunction:
    """
    漏洞函数
    NOTE:
        1. file_path: 源代码文件实际存储路径, 例如: "TestCases/model_train/model_1/test_data/p12_add.c", 不是文件相对项目的路径
    """

    file_path: str
    file_name: str
    function_name: str

    project_name: str = ""
    line_start: int = 0
    line_end: int = 0
    normalized_src_codes: List[str] = dataclasses.field(default_factory=list)

    patches: List[Patch] = dataclasses.field(default_factory=list)

    # bin function num
    bin_function_num: int = 0
    # possible bin functions
    possible_bin_functions: List[PossibleBinFunction] = dataclasses.field(default_factory=list)

    # summary
    possible_bin_function_num: int = 0
    possible_bin_function_names: List[str] = dataclasses.field(default_factory=list)

    vul_bin_function_num: int = 0  # match_possibility > 0.9
    vul_bin_function_names: List[str] = dataclasses.field(default_factory=list)

    repaired_bin_function_num: int = 0  # match_possibility > 0.9 and confirmed_snippet_count > 0
    repaired_bin_function_names: List[str] = dataclasses.field(default_factory=list)

    conclusion = False

    def summary(self):
        possible_bin_function_names = [f.function_name for f in self.possible_bin_functions]
        self.possible_bin_function_names = possible_bin_function_names
        self.possible_bin_function_num = len(possible_bin_function_names)

        vul_bin_functions = [f for f in self.possible_bin_functions if f.is_vul_function]
        self.vul_bin_function_names = [f.function_name for f in vul_bin_functions]
        self.vul_bin_function_num = len(vul_bin_functions)

        repaired_bin_functions = [f for f in self.possible_bin_functions if f.is_repaired]
        self.repaired_bin_function_names = [f.function_name for f in repaired_bin_functions]
        self.repaired_bin_function_num = len(repaired_bin_functions)

        if self.vul_bin_function_num > self.repaired_bin_function_num:
            self.conclusion = True

    def customer_serialize(self):
        return {
            "project_name": self.project_name,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "summary": {
                "conclusion": self.conclusion,
                "bin_function_num": self.bin_function_num,
                "possible_bin_function_num": self.possible_bin_function_num,
                "vul_bin_function_num": self.vul_bin_function_num,
                "repaired_bin_function_num": self.repaired_bin_function_num,
                "possible_bin_function_names": self.possible_bin_function_names,
                "vul_bin_function_names": self.vul_bin_function_names,
                "repaired_bin_function_names": self.repaired_bin_function_names
            },
            "line_start": self.line_start,
            "line_end": self.line_end,
            # "normalized_src_codes": self.normalized_src_codes,
            # "patches": [patch.customer_serialize() for patch in self.patches],
            "possible_bin_functions": [possible_bin_function.customer_serialize()
                                       for possible_bin_function in self.possible_bin_functions]
        }

    def short_summary_serialize(self):
        return {
            "project_name": self.project_name,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "conclusion": self.conclusion,
            "bin_function_num": self.bin_function_num,
            "possible_bin_function_num": self.possible_bin_function_num,
            "vul_bin_function_num": self.vul_bin_function_num,
            "repaired_bin_function_num": self.repaired_bin_function_num,
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
    cause_functions: List[CauseFunction] = dataclasses.field(default_factory=list)
    cause_function_num: int = 0
    confirmed_cause_function_num: int = 0
    conclusion: bool = False

    def init_from_commit_info(self, commit_info: dict):
        # TODO 从commit_info中初始化Vulnerability对象
        pass

    def customer_serialize(self):
        return {
            "cve_id": self.cve_id,
            "cve_link": self.cve_link,
            "title": self.title,
            "severity": self.severity,
            "description": self.description,
            "summary": {
                "conclusion": self.conclusion,
                "cause_function_num": self.cause_function_num,
                "confirmed_cause_function_num": self.confirmed_cause_function_num,
                "function_summary": [cause_function.short_summary_serialize()
                                     for cause_function in self.cause_functions],
            },
            "cause_functions": [cause_function.customer_serialize() for cause_function in self.cause_functions],
        }

    def summary(self):
        self.cause_function_num = len(self.cause_functions)
        self.confirmed_cause_function_num = len(
            [cause_function for cause_function in self.cause_functions if cause_function.conclusion])
        self.conclusion = self.confirmed_cause_function_num > 0


@dataclass
class CauseFunctionAnalysisInfo:
    cause_function_name: str
    confirmed_bin_function_name: str = None
    possible_bin_function_names: List[str] = dataclasses.field(default_factory=list)

    def customer_serialize(self):
        return {
            "cause_function_name": self.cause_function_name,
            "confirmed_bin_function_name": self.confirmed_bin_function_name,
            "possible_bin_function_names": self.possible_bin_function_names
        }


@dataclass
class BinaryAnalysisInfo:
    binary_path: str
    bin_function_num: int
    filtered_bin_function_num: int

    def customer_serialize(self):
        return {
            "binary_path": self.binary_path,
            "bin_function_num": self.bin_function_num,
            "filtered_bin_function_num": self.filtered_bin_function_num
        }


@dataclass
class VulAnalysisInfo:
    binary_analysis_info: BinaryAnalysisInfo
    cause_function_analysis_infos: List[CauseFunctionAnalysisInfo] = dataclasses.field(default_factory=list)

    def customer_serialize(self):
        return {
            "binary_analysis_info": self.binary_analysis_info.customer_serialize(),
            "cause_function_analysis_infos": [cause_function_analysis_info.customer_serialize()
                                              for cause_function_analysis_info in self.cause_function_analysis_infos]
        }


@dataclass
class ASM_CODE_SNIPPET_MAPPING:
    """
    通过AUTO_COMPILE 生成的数据
    {
                "function_name": function_name,
                "sub_function_name": sub_function_name,
                "real_file_path": real_file_path,
                "src_line_number": line_number,
                "is_discriminator": is_discriminator,
                "src_line": current_src_line,
                "asm_lines": asm_lines,
            }
    """
    function_name: str
    sub_function_name: str
    real_file_path: str
    src_line_number: int
    is_discriminator: bool
    src_line: str
    asm_lines: List[str]

    @classmethod
    def init_from_dict(cls, data: dict):
        return cls(
            function_name=data['function_name'],
            sub_function_name=data['sub_function_name'],
            real_file_path=data['real_file_path'],
            src_line_number=data['src_line_number'],
            is_discriminator=data['is_discriminator'],
            src_line=data['src_line'],
            asm_lines=data['asm_lines']
        )


@dataclass
class TrainFunction:
    def __init__(self, src_file_path: str, binary_base_dir: str):
        self.function_save_path = src_file_path
        self.binary_base_dir = binary_base_dir

        dir_path, file_name = os.path.split(src_file_path)
        file_name_without_ext, ext = os.path.splitext(file_name)
        self.file_name_without_ext = file_name_without_ext

        if ".c_" in file_name_without_ext:
            self.function_file_name, self.function_name = file_name_without_ext.split('.c_')
        elif '.h_' in file_name_without_ext:
            self.function_file_name, self.function_name = file_name_without_ext.split('.h_')
        else:
            err_msg = f"unexpected file name {file_name_without_ext}"
            raise Exception(err_msg)

        # 这个需要单独设置
        self.effective_src_line_num = 0

    def get_src_feature_path(self):
        return os.path.join(self.binary_base_dir, f"{self.file_name_without_ext}.src_feature.json")

    def get_binary_path(self, compiler, opt):
        return os.path.join(self.binary_base_dir, compiler, opt, f"{self.file_name_without_ext}.o")

    def get_dump_path(self, compiler, opt):
        return os.path.join(self.binary_base_dir, compiler, opt, f"{self.file_name_without_ext}.mapping")

    def get_asm_path(self, compiler, opt):
        return os.path.join(self.binary_base_dir, compiler, opt, f"{self.file_name_without_ext}.json")

    def customer_serialize(self):
        return {
            "function_save_path": self.function_save_path,
            "binary_base_dir": self.binary_base_dir,
            "effective_src_line_num": self.effective_src_line_num
        }

    @classmethod
    def init_from_dict(cls, data: dict):
        obj = cls(
            src_file_path=data['function_save_path'],
            binary_base_dir=data['binary_base_dir']
        )
        obj.effective_src_line_num = data.get('effective_src_line_num', 0)

        return obj

    def load_src_feature(self) -> SrcFunctionFeature | None:
        path = self.get_src_feature_path()
        if not os.path.exists(path):
            return None

        return SrcFunctionFeature.init_from_json_file(path)

    def load_asm_code_snippet_mappings(self, compiler, opt) -> List[ASM_CODE_SNIPPET_MAPPING] | None:
        """
        通过AUTO_COMPILE 生成的数据
        {
                    "function_name": function_name,
                    "sub_function_name": sub_function_name,
                    "real_file_path": real_file_path,
                    "src_line_number": line_number,
                    "is_discriminator": is_discriminator,
                    "src_line": current_src_line,
                    "asm_lines": asm_lines,
                }
        """
        path = self.get_asm_path(compiler, opt)
        # 文件不存在
        if not os.path.exists(path):
            return None

        # 空文件
        asm_dict = load_from_json_file(path)
        if not asm_dict:
            return None

        # 函数名搞错了
        if self.function_name not in asm_dict:
            return None

        mappings = []
        for mapping_dict in asm_dict[self.function_name]["asm_code_snippet_mappings"]:
            mappings.append(ASM_CODE_SNIPPET_MAPPING.init_from_dict(mapping_dict))
        return mappings

    def generate_model_1_train_data_item(self):
        src_function_feature = self.load_src_feature()
        if src_function_feature is None:
            return None

        asm_snippet_mappings = self.load_asm_code_snippet_mappings('gcc', 'O0')
        if not asm_snippet_mappings:
            return None

        all_asm_codes = []
        asm_codes = []
        src_body_start_line = 0
        start_flag = False
        for asm_snippet_mapping in asm_snippet_mappings:
            all_asm_codes.extend(asm_snippet_mapping.asm_lines)
            if not start_flag:
                if "{" in asm_snippet_mapping.src_line:
                    src_body_start_line = asm_snippet_mapping.src_line_number + 1
                    start_flag = True
                continue
            asm_codes.extend(asm_snippet_mapping.asm_lines)
        skip_line_num = src_body_start_line - src_function_feature.line_start
        positive_train_data_item = DataItemForFunctionConfirmModel(
            function_name=self.function_name,
            src_codes=src_function_feature.original_lines[skip_line_num:],
            src_strings=src_function_feature.strings,
            src_numbers=src_function_feature.numbers,
            asm_codes=asm_codes,
            bin_strings=[],
            bin_numbers=[],
            bin_function_name=self.function_name,
            label=1
        )

        return positive_train_data_item

    def generate_model_2_train_data_item(self):
        """
        最少10行源代码，才适合作为训练数据
        """
        # 必须要有源代码
        src_function_feature = self.load_src_feature()
        if src_function_feature is None:
            return None

        # 源代码至少10行
        src_codes = src_function_feature.original_lines
        if len(src_codes) < 10:
            return None

        # 必须要有汇编代码
        asm_snippet_mappings = self.load_asm_code_snippet_mappings('gcc', 'O0')
        if not asm_snippet_mappings:
            return None

        # 随机选择源代码片段
        src_part_start_index = random.randint(3, len(src_codes) - 4)  # 不要前三行，因为可能是函数声明，不要最后三行(-4)，片段至少3行
        src_part_end_index = src_part_start_index + random.randint(src_part_start_index, len(src_codes) - 1)
        question_src_codes = src_codes[src_part_start_index:src_part_end_index + 1]
        # print(
        #     f"src_codes length : {len(src_codes)}, start_line: {src_part_start_index}, end_line: {src_part_end_index}")

        # 找到对应的汇编代码片段
        asm_codes = []
        answer_asm_codes = []
        for asm_snippet_mapping in asm_snippet_mappings:
            asm_codes.extend(asm_snippet_mapping.asm_lines)
            if src_part_start_index <= asm_snippet_mapping.src_line_number <= src_part_end_index:
                answer_asm_codes.extend(asm_snippet_mapping.asm_lines)

        # 生成数据项
        data_item = DataItemForCodeSnippetPositioningModel(
            function_name=self.function_name,
            src_codes=question_src_codes,
            asm_codes=asm_codes,
            answer_asm_codes=answer_asm_codes
        )

        return data_item

    def generate_model_3_train_data_item(self):
        """
        这里只生成了正确答案，还需要再生成错误答案
            错误答案 1： 随机插入3行源代码
            错误答案 2： 随机移除3行源代码
            错误答案 3： 随机替换3行源代码
        """
        # 必须要有源代码
        src_function_feature = self.load_src_feature()
        if src_function_feature is None:
            return None

        # 源代码至少10行
        src_codes = src_function_feature.original_lines
        if len(src_codes) < 10:
            return None

        # 必须要有汇编代码
        asm_snippet_mappings = self.load_asm_code_snippet_mappings('gcc', 'O0')
        if not asm_snippet_mappings:
            return None

        # 随机选择源代码片段, 作为正确答案
        src_part_start_index = random.randint(3, len(src_codes) - 4)  # 开始点在 [3, -3]
        src_part_end_index = src_part_start_index + random.randint(src_part_start_index,
                                                                   src_part_start_index + 15)  # 选取不超过15行的源代码
        right_answer_src_codes = src_codes[src_part_start_index:src_part_end_index + 1]
        print(
            f"src_codes length : {len(src_codes)}, start_line: {src_part_start_index}, end_line: {src_part_end_index}")

        # 找到对应的汇编代码片段，作为问题
        asm_codes = []
        question_asm_codes = []
        for asm_snippet_mapping in asm_snippet_mappings:
            asm_codes.extend(asm_snippet_mapping.asm_lines)
            if src_part_start_index <= asm_snippet_mapping.src_line_number <= src_part_end_index:
                question_asm_codes.extend(asm_snippet_mapping.asm_lines)

        # 生成数据项
        DataItemForCodeSnippetConfirmModelMC(
            asm_codes=question_asm_codes,
            right_src_codes=right_answer_src_codes,
            wrong_src_codes=[]
        )

    @classmethod
    def check_data_items(cls):
        # 检查有多少个数据项
        pass


@dataclass
class LibraryVul:
    library_id: int
    library_name: str
    vendor: str
    platform: str
    version_id: int
    version_number: str
    public_id: str

    @classmethod
    def init_from_csv(cls, csv_path):
        import pandas as pd
        # load csv
        df = pd.read_csv(csv_path)
        # walk
        library_vuls = []
        for index, row in df.iterrows():
            public_id = row['public_id']
            library_id = row['library_id']
            library_name = row['library_name']
            vendor = row['vendor']
            platform = row['platform']
            version_id = row['version_id']
            version_number = row['version_number']
            library_vuls.append(cls(library_id, library_name, vendor, platform, version_id, version_number, public_id))
        library_vuls.sort(key=lambda x: x.public_id)
        library_vuls.sort(key=lambda x: x.version_number)
        library_vuls.sort(key=lambda x: x.library_name)

        return library_vuls


@dataclass
class VulDetail:
    """
      {
    "public_id": "CVE-2016-10746",
    "url": "https://github.com/libvirt/libvirt/commit/506e9d6c2d4baaf580d489fff0690c0ff2ff588.patch",
    "raw": "From 506e9d6c2d4baaf580d489fff0690c0ff2ff588f Mon Sep 17 00:00:00 2001\nFrom: Michal Privoznik <mprivozn@redhat.com>\nDate: Mon, 11 Jan 2016 13:34:17 +0100\nSubject: [PATCH] virDomainGetTime: Deny on RO connections\n\nWe have a policy that if API may end up talking to a guest agent\nit should require RW connection. We don't obey the rule in\nvirDomainGetTime().\n\nSigned-off-by: Michal Privoznik <mprivozn@redhat.com>\n---\n src/libvirt-domain.c |    1 +\n 1 files changed, 1 insertions(+), 0 deletions(-)\n\ndiff --git a/src/libvirt-domain.c b/src/libvirt-domain.c\nindex 02fc4df..9491845 100644\n--- a/src/libvirt-domain.c\n+++ b/src/libvirt-domain.c\n@@ -10934,6 +10934,7 @@ virDomainGetTime(virDomainPtr dom,\n     virResetLastError();\n \n     virCheckDomainReturn(dom, -1);\n+    virCheckReadOnlyGoto(dom->conn->flags, error);\n \n     if (dom->conn->driver->domainGetTime) {\n         int ret = dom->conn->driver->domainGetTime(dom, seconds,\n-- \n1.7.1\n\n",
    "hunk_code": "@@ -10934,6 +10934,7 @@ virDomainGetTime(virDomainPtr dom,\n     virResetLastError();\n \n     virCheckDomainReturn(dom, -1);\n+    virCheckReadOnlyGoto(dom->conn->flags, error);\n \n     if (dom->conn->driver->domainGetTime) {\n         int ret = dom->conn->driver->domainGetTime(dom, seconds,\n",
    "affected_file": "b/src/libvirt-domain.c",
    "affected_function": ""
  },
    """
    public_id: str
    url: str
    raw: str
    hunk_code: str
    affected_file: str
    affected_function: str

    def __hash__(self):
        return hash(
            f"{self.public_id}-{self.url}-{self.raw}-{self.hunk_code}-{self.affected_file}-{self.affected_function}")

    def __eq__(self, other):
        return (self.public_id == other.public_id
                and self.url == other.url
                and self.raw == other.raw
                and self.hunk_code == other.hunk_code
                and self.affected_file == other.affected_file
                and self.affected_function == other.affected_function)

    @classmethod
    def init_from_json(cls, json_path):
        json_items = load_from_json_file(json_path)
        vul_details = []
        for json_item in json_items:
            public_id = json_item['public_id']
            url = json_item['url']
            raw = json_item['raw']
            hunk_code = json_item['hunk_code']
            affected_file = json_item['affected_file']
            affected_function = json_item['affected_function']
            vul_details.append(cls(public_id, url, raw, hunk_code, affected_file, affected_function))
        vul_details.sort(key=lambda x: x.public_id)
        return vul_details

    @classmethod
    def load_all_effective_vul_details(cls, json_dir_path):
        # load
        file_names = os.listdir(json_dir_path)
        file_paths = [os.path.join(json_dir_path, file_name) for file_name in file_names if file_name.endswith('.json')]
        vul_details = []
        for json_path in file_paths:
            try:
                vul_details.extend(cls.init_from_json(json_path))
            except Exception as e:
                print(f"load {json_path} failed, {e}")

        # filter
        vul_detail_dict = {}
        for vul_detail in vul_details:
            ext = os.path.splitext(vul_detail.affected_file)[-1]
            if ext in {'.c', '.cpp', '.h', '.hpp', '.cc'} and vul_detail.raw and vul_detail.hunk_code:
                public_id = vul_detail.public_id
                if (details := vul_detail_dict.get(public_id)) is None:
                    vul_detail_dict[public_id] = details = []
                details.append(vul_detail)

        # deduplication
        for public_id, details in vul_detail_dict.items():
            vul_detail_dict[public_id] = list(set(details))

        return vul_detail_dict


@dataclass
class CodeMapping(Serializable):
    src_function_name: str = None
    src_function_path: str = None
    src_code_line_num: int = None

    is_discriminator: bool = False
    asm_codes: List[str] = dataclasses.field(default_factory=list)
    src_codes: List[str] = dataclasses.field(default_factory=list)


@dataclass
class AsmFunction(Serializable):
    function_name: str
    code_mappings: List[CodeMapping]

    def get_key(self):
        asm_function_path = self.code_mappings[0].src_function_path
        asm_function_path = asm_function_path.split("__tmp/")[-1]
        if asm_function_path.startswith("./"):
            asm_function_path = asm_function_path[2:]

        return f"{asm_function_path}__{self.function_name}"
    def get_param_num(self):
        for code_mapping in self.code_mappings:
            for line in code_mapping.src_codes:
                if "(" in line:
                    return line.count(",") + 1
        return 0
    def get_asm_codes(self, skip_function_def=False):
        if skip_function_def:
            start_flag = False
            start_index = 0
            for i, code_mapping in enumerate(self.code_mappings):
                for line in code_mapping.src_codes:
                    if "{" in line:
                        start_flag = True
                if start_flag:
                    start_index = i + 1
                    if start_index >= len(self.code_mappings):
                        start_index = len(self.code_mappings) - 1
                    break

            asm_codes = [asm_code
                         for code_mapping in self.code_mappings[start_index:]
                         for asm_code in code_mapping.asm_codes]
            src_code_start_line = self.code_mappings[start_index].src_code_line_num
        else:
            asm_codes = [asm_code
                         for code_mapping in self.code_mappings
                         for asm_code in code_mapping.asm_codes]
            src_code_start_line = self.code_mappings[0].src_code_line_num
        return asm_codes, src_code_start_line

    def count_asm_codes(self):
        asm_codes, src_code_start_line = self.get_asm_codes()
        return len(asm_codes)

