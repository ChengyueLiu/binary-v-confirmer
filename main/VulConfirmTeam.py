import os
from typing import List

import torch
from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.interface import CauseFunction, ConfirmAnalysis, Vulnerability, PossibleBinFunction, PossibleAsmSnippet
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

    def confirm(self, binary_path, vul: Vulnerability):
        for cause_function in vul.cause_functions:
            # 1. 定位漏洞函数
            normalized_src_codes, bin_function_num, possible_bin_functions = self.function_finder.find_similar_bin_functions(
                src_file_path=cause_function.file_path,
                function_name=cause_function.function_name,
                binary_file_abs_path=os.path.abspath(binary_path))
            cause_function.bin_function_num = bin_function_num
            cause_function.normalized_src_codes = normalized_src_codes
            cause_function.possible_bin_functions = possible_bin_functions
            logger.info(f"possible_bin_functions: {len(possible_bin_functions)}")

            for i, possible_bin_function in enumerate(possible_bin_functions, start=1):
                logger.info(
                    f"{i}: function：{cause_function.function_name} ---> bin_function: {possible_bin_function.function_name}, "
                    f"personality: {possible_bin_function.match_possibility}")

                # 函数是否确认漏洞
                if possible_bin_function.match_possibility < 0.9:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = "match_possibility < 0.9"
                    continue

                # 2. 定位漏洞代码片段
                patch_src_codes_text, asm_codes_window_texts = self.snippet_positioner.position(
                    vul_function_name=cause_function.function_name,
                    src_codes=cause_function.patches[0].snippet_codes_after_commit,
                    asm_codes=possible_bin_function.asm_codes)
                cause_function.patches[0].snippet_codes_text_after_commit = patch_src_codes_text
                possible_bin_function.asm_codes_window_texts = asm_codes_window_texts
                if len(asm_codes_window_texts) == 0:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = "len(asm_codes_window_texts) == 0"
                    continue
                logger.info(
                    f"len(asm_codes): {len(possible_bin_function.asm_codes)} ---> len(asm_codes_texts): {len(asm_codes_window_texts)}")

                # 3. 确认漏洞代码片段
                predictions = self.snippet_confirmer.confirm_vuls(patch_src_codes_text,
                                                                  asm_codes_window_texts)

                for i, (asm_codes_window_text, (pred, prob)) in enumerate(zip(asm_codes_window_texts, predictions)):
                    logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(asm_codes_window_text, pred.item(), prob.item())
                    possible_bin_function.possible_asm_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.confirmed_snippet_count += 1

                # 函数是否确认漏洞
                if possible_bin_function.confirmed_snippet_count > 0:
                    possible_bin_function.conclusion = True
                    possible_bin_function.judge_reason = f"confirmed_snippet_count = {possible_bin_function.confirmed_snippet_count}"

                else:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = f"confirmed_snippet_count = {possible_bin_function.confirmed_snippet_count}"

            cause_function.summary()


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
