from dataclasses import dataclass
from typing import List

from loguru import logger

from bintools.general.file_tool import load_from_json_file


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
    def init_from_dict(cls, data: dict):
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


class TrainDataItemForModel1:
    def __init__(self, function_feature: FunctionFeature):
        """
        从原始特征中初始化训练数据
        :param function_feature:
        """

        # 部分源代码函数会重名，二进制中的函数不会重名，为了省事儿，重名的直接不用，避免对应错误
        self.src_function_feature = function_feature.src_function_features[0]
        self.bin_function_feature = function_feature.bin_function_feature

        # 正规化处理
        self._normalize_src_function_feature()
        self._normalize_bin_function_feature()

        # 赋值
        self.function_name = function_feature.function_name
        self.src_codes: List[str] = self.src_function_feature.original_lines
        self.src_strings: List[str] = self.src_function_feature.strings
        self.src_numbers: List[int] = self.src_function_feature.numbers
        self.asm_codes: List[str] = self.bin_function_feature.asm_codes
        self.bin_strings: List[str] = self.bin_function_feature.strings
        self.bin_numbers: List[int] = self.bin_function_feature.numbers

    def custom_serialize(self):
        return {
            "function_name": self.function_name,
            # "src_codes": self.src_codes,
            "src_strings": self.src_strings,
            "src_numbers": self.src_numbers,
            # "asm_codes": self.asm_codes,
            "bin_strings": self.bin_strings,
            "bin_numbers": self.bin_numbers
        }

    def _normalize_src_function_feature(self):
        # 正规化处理源代码
        self.src_function_feature.original_lines = [self._normalize_src_code(line)
                                                    for line in self.src_function_feature.original_lines]

        # 正规化处理字符串
        self.src_function_feature.strings = [self._normalize_src_string(s)
                                             for s in self.src_function_feature.strings if s]

        # 正规化处理数字
        self.src_function_feature.numbers = [self._normalize_src_number(n)
                                             for n in self.src_function_feature.numbers]

    def _normalize_bin_function_feature(self):
        # 正规化处理汇编代码
        self.bin_function_feature.asm_codes = [self._normalize_bin_code(code)
                                               for code in self.bin_function_feature.asm_codes]

        # 正规化处理字符串
        self.bin_function_feature.strings = [self._normalize_bin_string(s)
                                             for s in self.bin_function_feature.strings if s]

        # 正规化处理数字
        self.bin_function_feature.numbers = [self._normalize_bin_number(n)
                                             for n in self.bin_function_feature.numbers]

    def _normalize_src_code(self, src_code: str):
        # 正规化处理源代码
        return src_code

    def _normalize_src_string(self, src_string: str):
        return src_string

    def _normalize_src_number(self, src_number: int):
        # 正规化处理数字
        return src_number

    def _normalize_bin_code(self, bin_code: str):
        # 正规化处理汇编代码
        bin_code = bin_code.split(";")[0]
        return bin_code

    def _normalize_bin_string(self, bin_string: str):
        # 正规化处理字符串
        return bin_string

    def _normalize_bin_number(self, bin_number: int):
        # 正规化处理数字
        return bin_number
