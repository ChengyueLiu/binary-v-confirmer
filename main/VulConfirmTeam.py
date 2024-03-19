import os
from typing import List

import torch
from loguru import logger

from main.interface import Vulnerability, Result
from main.models.code_snippet_confirm_model.model_application import SnippetConfirmer
from main.models.code_snippet_positioning_model.model_application import SnippetPositioner
from main.models.function_confirm_model.model_application import FunctionFinder


class VulConfirmTeam:
    def __init__(self, function_confirm_model_pth_path,
                 snippet_positioning_model_pth_path,
                 snippet_confirm_model_pth_path,
                 batch_size=16):
        # 定位漏洞函数
        logger.info("init function_finder")
        self.function_finder = FunctionFinder(model_save_path=function_confirm_model_pth_path, batch_size=batch_size)
        logger.info("init snippet_positioner")
        self.snippet_positioner = SnippetPositioner(model_save_path=snippet_positioning_model_pth_path,
                                                    batch_size=batch_size)
        logger.info("init snippet_confirmer")
        self.snippet_confirmer = SnippetConfirmer(model_save_path=snippet_confirm_model_pth_path, batch_size=batch_size)
        logger.info("VulConfirmTeam init done")

    def confirm(self, binary_path, vul: Vulnerability):
        # TODO 今天要实现一个完整的代码，先不管正确率，然后要准备一个测试用例，之后才是调试
        # 1. 定位漏洞函数
        results: List[Result] = self.function_finder.find_binary_functions(
            src_file_path=vul.file_path,
            vul_function_name=vul.function_name,
            binary_file_abs_path=os.path.abspath(binary_path))

        final_results = []
        for result in results[:3]:
            print(
                f"function：{result.function_name} ---> bin_function: {result.bin_function_name}, personality: {result.function_match_possibility}")
            # 2. 定位漏洞代码片段
            src_codes_text, asm_codes_texts = self.snippet_positioner.position(vul_function_name=vul.function_name,
                                                                               src_codes=result.src_codes,
                                                                               asm_codes=result.asm_codes)
            result.src_codes_text = src_codes_text
            result.asm_codes_texts = asm_codes_texts

            # 3. 确认漏洞代码片段
            predictions = self.snippet_confirmer.confirm_vuls(src_codes_text,
                                                              asm_codes_texts)
            result.snippet_match_possibilities = predictions
            print(predictions)
            # 4. 返回确认结果
            final_results.append(result)

        return final_results
