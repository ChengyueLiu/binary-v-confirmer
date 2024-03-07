from dataclasses import dataclass
from typing import List


@dataclass
class SrcFunctionFeature:
    name: str
    original_lines: List[str]
    strings: List[str]
    numbers: List[int]
    hash_value: str


@dataclass
class SrcProjectFeature:
    name: str
    functions: List[SrcFunctionFeature]


@dataclass
class AsmFunctionFeature:
    name: str
    original_lines: List[str]
    strings: List[str]
    numbers: List[int]
    hash_value: str


@dataclass
class AsmProjectFeature:
    name: str
    functions: List[AsmFunctionFeature]


@dataclass
class TrainItem:
    src_function_feature: SrcFunctionFeature
    asm_function_feature: AsmFunctionFeature
