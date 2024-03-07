from dataclasses import dataclass
from typing import List


@dataclass
class SrcFunctionFeature:
    name: str
    original_lines: List[str]
    strings: List[str]
    numbers: List[int]
    hash_value: str

    def custom_serialize(self):
        return {
            "name": self.name,
            "original_lines": self.original_lines,
            "strings": self.strings,
            "numbers": self.numbers,
            "hash_value": self.hash_value
        }


@dataclass
class AsmFunctionFeature:
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

    def custom_serialize(self):
        return {
            "name": self.name,
            "asm_codes": self.asm_codes,
            "strings": self.strings,
            "numbers": self.numbers
        }


@dataclass
class SrcProjectFeature:
    name: str
    functions: List[SrcFunctionFeature]


@dataclass
class AsmProjectFeature:
    name: str
    functions: List[AsmFunctionFeature]


@dataclass
class TrainItem:
    src_function_feature: SrcFunctionFeature
    asm_function_feature: AsmFunctionFeature
