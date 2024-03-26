import os
import time

from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.interface import Vulnerability, PossibleAsmSnippet
from main.models.code_snippet_confirm_model.model_application import SnippetConfirmer
from main.models.code_snippet_positioning_model.model_application import SnippetPositioner
from main.models.function_confirm_model.model_application import FunctionFinder
from setting.settings import CAUSE_FUNCTION_SIMILARITY_THRESHOLD, POSSIBLE_BIN_FUNCTION_TOP_N


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

    def confirm_snippet(self, cause_function, possible_bin_function, is_vul=True):
        """
        定位，确认漏洞代码片段
        :param cause_function:
        :param possible_bin_function:
        :param is_vul:
        :return:
        """
        # 2. 定位代码片段
        # TODO 可能会有多个patch，这里只取第一个patch
        patch = cause_function.patches[0]
        # 源代码片段
        if is_vul:
            src_codes = patch.snippet_codes_before_commit
        else:
            src_codes = patch.snippet_codes_after_commit
        # 定位代码片段
        src_codes_text, asm_codes_window_texts = self.snippet_positioner.position(
            vul_function_name=cause_function.function_name,
            src_codes=src_codes,
            asm_codes=possible_bin_function.asm_codes)

        # 更新代码片段text
        if is_vul:
            cause_function.patches[0].snippet_codes_text_before_commit = src_codes_text
        else:
            cause_function.patches[0].snippet_codes_text_after_commit = src_codes_text
        if len(asm_codes_window_texts) == 0:
            return "", [], []
        # logger.info(
        #     f"len(asm_codes): {len(possible_bin_function.asm_codes)} ---> len(asm_codes_texts): {len(asm_codes_window_texts)}")

        # 3. 确认代码片段
        predictions = self.snippet_confirmer.confirm_vuls(src_codes_text, asm_codes_window_texts)
        return src_codes_text, asm_codes_window_texts, predictions

    def confirm(self, binary_path, vul: Vulnerability):
        logger.info(f"Start confirm {vul.cve_id} in {binary_path}")
        start_at = time.perf_counter()
        for cause_function in vul.cause_functions:
            # 1. Model 1 函数确认
            logger.info(f"{cause_function.function_name}: start confirm")
            normalized_src_codes, bin_function_num, possible_bin_functions = self.function_finder.find_similar_bin_functions(
                src_file_path=cause_function.file_path,
                function_name=cause_function.function_name,
                binary_file_abs_path=os.path.abspath(binary_path))
            # 正规化的源代码
            cause_function.normalized_src_codes = normalized_src_codes
            # 全部的二进制函数数量
            cause_function.bin_function_num = bin_function_num
            # label为1且概率大于阈值的二进制函数, 按照概率排序，取前n个
            # label为1且概率大于阈值的二进制函数, 按照概率排序，取前n个
            # 筛选
            for possible_bin_function in possible_bin_functions:
                if possible_bin_function.match_possibility <= CAUSE_FUNCTION_SIMILARITY_THRESHOLD:
                    continue
                if len(possible_bin_function.asm_codes) <= 3:
                    continue
                cause_function.possible_bin_functions.append(possible_bin_function)
            # 排序，取前n个
            cause_function.possible_bin_functions = sorted(cause_function.possible_bin_functions,
                                                           key=lambda x: x.match_possibility, reverse=True)[
                                                    :POSSIBLE_BIN_FUNCTION_TOP_N]

            for i, possible_bin_function in enumerate(cause_function.possible_bin_functions, start=1):
                # 2. Model 2 定位漏洞片段
                vul_src_codes_text, vul_asm_codes_window_texts, vul_predictions = self.confirm_snippet(
                    cause_function,
                    possible_bin_function,
                    is_vul=True)

                # 3. Model 3 确认漏洞片段
                for asm_codes_window_text, (pred, prob) in zip(vul_asm_codes_window_texts, vul_predictions):
                    # logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(vul_src_codes_text, asm_codes_window_text, pred.item(), prob.item())
                    possible_bin_function.possible_vul_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.has_vul_snippet = True
                        possible_bin_function.confirmed_vul_snippet_count += 1

                # 4. Model 2 定位补丁片段
                patch_src_codes_text, patch_asm_codes_window_texts, patch_predictions = self.confirm_snippet(
                    cause_function,
                    possible_bin_function,
                    is_vul=False)

                # 5. Model 4 确认补丁片段
                for asm_codes_window_text, (pred, prob, scores) in zip(patch_asm_codes_window_texts, patch_predictions):
                    # logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(patch_src_codes_text, asm_codes_window_text, pred.item(), prob.item(),
                                             scores=scores)
                    possible_bin_function.possible_patch_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.has_patch_snippet = True
                        possible_bin_function.confirmed_patch_snippet_count += 1

                # 6. 判定是否是漏洞函数，并记录判定原因
                # 如果没有漏洞函数，判定为False
                if possible_bin_function.confirmed_vul_snippet_count == 0:
                    possible_bin_function.is_vul_function = False
                    possible_bin_function.judge_reason = "confirmed_vul_snippet_count == 0"
                else:
                    possible_bin_function.is_vul_function = True
                    # 如果有漏洞函数，则补丁更多，判定为修复
                    if possible_bin_function.confirmed_patch_snippet_count >= possible_bin_function.confirmed_vul_snippet_count:
                        possible_bin_function.is_repaired = True
                    else:
                        possible_bin_function.is_repaired = False
                    possible_bin_function.judge_reason = f"possible_bin_function = {possible_bin_function.confirmed_vul_snippet_count}, " \
                                                         f"confirmed_patch_snippet_count = {possible_bin_function.confirmed_patch_snippet_count}"
            cause_function.summary()
        vul.summary()
        logger.info(f"Confirm Done, Time cost: {round(time.perf_counter() - start_at, 2)}s")


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
