import os

from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.interface import Vulnerability, PossibleAsmSnippet
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

    def confirm_snippet(self, cause_function, possible_bin_function, is_vul=True):
        """
        定位，确认漏洞代码片段
        :param cause_function:
        :param possible_bin_function:
        :param is_vul:
        :return:
        """
        # 2. 定位漏洞代码片段
        patch = cause_function.patches[0]
        src_codes = patch.snippet_codes_before_commit if is_vul else patch.snippet_codes_after_commit
        patch_src_codes_text, asm_codes_window_texts = self.snippet_positioner.position(
            vul_function_name=cause_function.function_name,
            src_codes=src_codes,
            asm_codes=possible_bin_function.asm_codes)
        cause_function.patches[0].snippet_codes_text_after_commit = patch_src_codes_text
        possible_bin_function.asm_codes_window_texts = asm_codes_window_texts
        if len(asm_codes_window_texts) == 0:
            return [], []
        logger.info(
            f"len(asm_codes): {len(possible_bin_function.asm_codes)} ---> len(asm_codes_texts): {len(asm_codes_window_texts)}")

        # 3. 确认漏洞代码片段
        predictions = self.snippet_confirmer.confirm_vuls(patch_src_codes_text,
                                                          asm_codes_window_texts)
        return asm_codes_window_texts, predictions

    def confirm(self, binary_path, vul: Vulnerability):
        for cause_function in vul.cause_functions:
            # 1. 定位漏洞函数
            normalized_src_codes, bin_function_num, possible_bin_functions = self.function_finder.find_similar_bin_functions(
                src_file_path=cause_function.file_path,
                function_name=cause_function.function_name,
                binary_file_abs_path=os.path.abspath(binary_path))
            cause_function.normalized_src_codes = normalized_src_codes
            cause_function.bin_function_num = bin_function_num
            cause_function.possible_bin_functions = possible_bin_functions
            logger.info(f"possible_bin_functions: {len(possible_bin_functions)}")

            for i, possible_bin_function in enumerate(possible_bin_functions, start=1):
                # 跳过源代码函数比二进制函数长的情况，这种基本都是误判
                # if (asm_codes_length := len(possible_bin_function.asm_codes)) <= (
                #         src_codes_length := len(normalized_src_codes)):
                #     possible_bin_function.conclusion = False
                #     possible_bin_function.judge_reason = f"asm_codes_length({asm_codes_length}) <= src_codes_length({src_codes_length})"
                #     continue

                # 可能性很小的函数直接跳过
                min_match_possibility = 0.9
                if possible_bin_function.match_possibility < min_match_possibility:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = f"match_possibility < {min_match_possibility}"
                    continue

                # 确认漏洞片段
                vul_asm_codes_window_texts, vul_predictions = self.confirm_snippet(cause_function,
                                                                                   possible_bin_function,
                                                                                   is_vul=True)
                # 更新漏洞片段信息
                for asm_codes_window_text, (pred, prob) in zip(vul_asm_codes_window_texts, vul_predictions):
                    logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(asm_codes_window_text, pred.item(), prob.item())
                    possible_bin_function.possible_vul_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.confirmed_vul_snippet_count += 1

                # 确认补丁片段
                patch_asm_codes_window_texts, patch_predictions = self.confirm_snippet(cause_function,
                                                                                       possible_bin_function,
                                                                                       is_vul=False)
                if not patch_asm_codes_window_texts:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = "len(asm_codes_window_texts) == 0"
                    continue

                # 更新补丁片段信息
                for asm_codes_window_text, (pred, prob) in zip(patch_asm_codes_window_texts, patch_predictions):
                    logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(asm_codes_window_text, pred.item(), prob.item())
                    possible_bin_function.possible_patch_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.confirmed_patch_snippet_count += 1

                # 判定这个函数
                # 如果没有确认的漏洞片段，直接判定为False
                if possible_bin_function.confirmed_vul_snippet_count == 0:
                    possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = "confirmed_vul_snippet_count == 0"

                else:
                    # 如果确认的漏洞片段数大于确认的补丁片段数，判定为True
                    if possible_bin_function.confirmed_patch_snippet_count < possible_bin_function.confirmed_vul_snippet_count:
                        possible_bin_function.conclusion = True
                    # 如果确认的漏洞片段数小于等于确认的补丁片段数，判定为False
                    else:
                        possible_bin_function.conclusion = False
                    possible_bin_function.judge_reason = (
                        f"confirmed_vul_snippet_count = {possible_bin_function.confirmed_vul_snippet_count}, "
                        f"confirmed_patch_snippet_count = {possible_bin_function.confirmed_patch_snippet_count}")

                logger.info(
                    f"{i}: {cause_function.function_name} ---> {possible_bin_function.function_name}: {possible_bin_function.conclusion}. \n"
                    f"reason: {possible_bin_function.judge_reason}")
            cause_function.summary()
        vul.summary()


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
