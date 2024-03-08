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


class TrainDataItemForFunctionConfirmModel:
    src_code_separator = "[SRC_CODE]"
    src_string_separator = "[SRC_STR]"
    src_number_separator = "[SRC_NUM]"
    asm_code_separator = "[ASM_CODE]"
    bin_string_separator = "[BIN_STR]"
    bin_number_separator = "[BIN_NUM]"

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
                cls.bin_number_separator]

    def get_train_text(self):
        src_code_text = " ".join(self.src_codes)
        src_strings = " ".join([self.function_name, *self.src_strings])
        src_numbers = " ".join([str(num) for num in self.src_numbers])
        src_text = f"{self.src_code_separator} {src_code_text} {self.src_string_separator} {src_strings} {self.src_number_separator} {src_numbers}"

        asm_code_text = " ".join(self.asm_codes)
        bin_strings = " ".join(self.bin_strings)
        bin_numbers = " ".join([str(num) for num in self.bin_numbers])
        bin_text = f"{self.asm_code_separator} {asm_code_text} {self.bin_string_separator} {bin_strings} {self.bin_number_separator} {bin_numbers}"

        merged_text = f"{src_text} {bin_text}"
        return merged_text

    def _normalize(self):
        # 正规化处理源代码
        self.src_codes = [self._normalize_src_code(line) for line in self.src_codes]

        # 正规化处理字符串
        self.src_strings = [self._normalize_src_string(s) for s in self.src_strings]

        # 正规化处理数字
        self.src_numbers = [self._normalize_src_number(num) for num in self.src_numbers]

        # 正规化处理汇编代码
        self.asm_codes = [self._normalize_bin_code(code) for code in self.asm_codes]

        # 正规化处理字符串
        self.bin_strings = [self._normalize_bin_string(s) for s in self.bin_strings]

        # 正规化处理数字
        self.bin_numbers = [self._normalize_bin_number(num) for num in self.bin_numbers]

    def _normalize_src_code(self, src_code: str):
        # 正规化处理源代码
        return src_code

    def _normalize_src_string(self, src_string: str):
        return src_string

    def _normalize_src_number(self, src_number: str):
        # 正规化处理数字
        return src_number

    def _normalize_bin_code(self, bin_code: str):
        # 正规化处理汇编代码
        bin_code = bin_code.split(";")[0]
        return bin_code

    def _normalize_bin_string(self, bin_string: str):
        # 正规化处理字符串
        return bin_string

    def _normalize_bin_number(self, bin_number: str):
        # 正规化处理数字
        return bin_number
