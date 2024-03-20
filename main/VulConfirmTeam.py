import os
from typing import List

import torch
from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.interface import CauseFunction, Result
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

    def confirm(self, binary_path, cause_function: CauseFunction) -> Result:
        # 1. 定位漏洞函数
        src_codes, possible_bin_functions = self.function_finder.find_binary_functions(
            cause_function=cause_function,
            binary_file_abs_path=os.path.abspath(binary_path))
        cause_function.src_codes = src_codes

        final_possible_bin_functions = []
        for possible_function in possible_bin_functions[:3]:
            logger.info(
                f"function：{cause_function.function_name} ---> bin_function: {possible_function.function_name}, "
                f"personality: {possible_function.match_possibility}")

            # 2. 定位漏洞代码片段
            src_codes_text, asm_codes_texts = self.snippet_positioner.position(
                vul_function_name=cause_function.function_name,
                src_codes=src_codes,
                asm_codes=possible_function.asm_codes)
            cause_function.src_codes_text = src_codes_text

            logger.info(
                f"len(asm_codes): {len(possible_function.asm_codes)} ---> len(asm_codes_texts): {len(asm_codes_texts)}")
            possible_function.asm_codes_window_texts = asm_codes_texts

            # 3. 确认漏洞代码片段
            predictions = self.snippet_confirmer.confirm_vuls(src_codes_text,
                                                              asm_codes_texts)
            for i, (pred, prob) in enumerate(predictions):
                logger.info(f"pred: {pred}, prob: {prob}")
                possible_function.predictions.append((pred, prob))
            # 4. 返回确认结果
            final_possible_bin_functions.append(possible_function)
        result = Result(
            cause_function=cause_function,
            possible_bin_functions=final_possible_bin_functions
        )
        return result


def confirm_vul(vul_confirm_team: VulConfirmTeam, binary_path, vul: CauseFunction, save_path):
    """
    confirm vul and save result to json file

    :param vul_confirm_team:
    :param binary_path:
    :param vul:
    :param save_path:

    :return:
    """
    # init confirm team

    # confirm vul
    result = vul_confirm_team.confirm(binary_path=binary_path, cause_function=vul)

    # save result to json file
    save_to_json_file(result.customer_serialize(), save_path, output_log=True)
