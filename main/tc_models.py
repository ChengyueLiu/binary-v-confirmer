from dataclasses import dataclass
from typing import List

from main.interface import Serializable


# ----- 以下是测试用例 -----
@dataclass
class VulFunctionPatch(Serializable):
    vul_snippet_codes: List[str]
    fixed_snippet_codes: List[str]


@dataclass
class VulFunction(Serializable):
    # function
    function_name: str  # 函数名
    vul_source_codes: List[str]  # 修复前的函数源代码
    patches: List[VulFunctionPatch]  # 修复补丁

    def get_function_name(self):
        if self.function_name.startswith("*"):
            return self.function_name[1:]
        return self.function_name

    def get_source_codes(self, skip_func_def=False):
        if skip_func_def:
            source_codes = []
            start_flag = False
            for code in self.vul_source_codes:
                if "{" in code:
                    start_flag = True
                    continue
                if start_flag:
                    source_codes.append(code)
            return source_codes
        else:
            return self.vul_source_codes


@dataclass
class TestBin(Serializable):
    # library
    library_name: str
    version_number: str
    version_tag: str

    # binary
    binary_name: str = None
    binary_path: str = None


@dataclass
class GroundTruth(Serializable):
    contained_vul_function_names: List[str]  # 测试二进制中包含的漏洞函数名
    is_fixed: bool  # 测试二进制文件的漏洞函数是否已经修复


@dataclass
class VulConfirmTC(Serializable):
    public_id: str
    affected_library: str

    vul_functions: List[VulFunction]

    test_bin: TestBin = None

    ground_truth: GroundTruth = None

    def is_effective(self):
        if not self.test_bin.binary_name:
            return False

        for function in self.vul_functions:
            if function.vul_source_codes:
                return True

        return False