import os
from typing import List

import torch
from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.interface import CauseFunction, ConfirmAnalysis, Vulnerability, PossibleBinFunction
from main.models.code_snippet_confirm_model.model_application import SnippetConfirmer
from main.models.code_snippet_positioning_model.model_application import SnippetPositioner
from main.models.function_confirm_model.model_application import FunctionFinder


class VulConfirmTeam:
    def __init__(self, function_confirm_model_pth_path=r"Resources/model_weights/model_1_weights.pth",
                 snippet_positioning_model_pth_path=r"Resources/model_weights/model_2_weights.pth",
                 snippet_confirm_model_pth_path=r"Resources/model_weights/model_3_weights.pth",
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

    def confirm(self, binary_path, vul: Vulnerability) -> ConfirmAnalysis:
        analysis = ConfirmAnalysis(
            vulnerability=vul,
        )

        # 1. 定位漏洞函数
        possible_bin_functions: List[PossibleBinFunction] = self.function_finder.find_similar_bin_functions(
            src_file_path=vul.cause_function.file_path,
            function_name=vul.cause_function.function_name,
            binary_file_abs_path=os.path.abspath(binary_path),
            analysis=analysis)

        for possible_bin_function in possible_bin_functions:
            logger.info(
                f"function：{vul.cause_function.function_name} ---> bin_function: {possible_bin_function.function_name}, "
                f"personality: {possible_bin_function.match_possibility}")

            # 2. 定位漏洞代码片段
            patch_src_codes_text, asm_codes_window_texts = self.snippet_positioner.position(
                vul_function_name=vul.cause_function.function_name,
                src_codes=vul.patches[0].snippet_codes_after_commit,
                asm_codes=possible_bin_function.asm_codes)
            vul.patches[0].snippet_codes_text_after_commit = patch_src_codes_text

            logger.info(
                f"len(asm_codes): {len(possible_bin_function.asm_codes)} ---> len(asm_codes_texts): {len(asm_codes_window_texts)}")
            vul.patches[0].snippet_codes_text_after_commit = patch_src_codes_text
            possible_bin_function.asm_codes_window_texts = asm_codes_window_texts

            # 3. 确认漏洞代码片段
            predictions = self.snippet_confirmer.confirm_vuls(patch_src_codes_text,
                                                              asm_codes_window_texts)
            for i, (pred, prob) in enumerate(predictions):
                logger.info(f"pred: {pred}, prob: {prob}")
                possible_bin_function.predictions.append((pred, prob))

        return analysis


def confirm_vul(binary_path, vul: Vulnerability, analysis_file_save_path=None) -> bool:
    """
    To confirm whether the vulnerability is in the binary file

    :param binary_path:
    :param vul:
    :param analysis_file_save_path:

    :return:
    """
    # step 1: init VulConfirmTeam
    vul_confirm_team = VulConfirmTeam()

    # confirm vul
    result = vul_confirm_team.confirm(binary_path=binary_path, cause_function=vul)

    # save result to json file
    if analysis_file_save_path:
        save_to_json_file(result.customer_serialize(), analysis_file_save_path, output_log=True)

    return True
