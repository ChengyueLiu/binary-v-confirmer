import os
import time
from typing import Optional, List

from loguru import logger

from bintools.general.file_tool import save_to_json_file, load_from_json_file
from bintools.general.normalize import remove_comments
from main.extractors.function_feature_extractor import extract_src_feature_for_specific_function
from main.interface import Vulnerability, PossibleAsmSnippet, BinFunctionFeature, SrcFunctionFeature, VulAnalysisInfo, \
    CauseFunctionAnalysisInfo, BinaryAnalysisInfo
from main.models.code_snippet_confirm_model.model_application import SnippetConfirmer
from main.models.code_snippet_confirm_model_multi_choice.model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.model_application import SnippetPositioner
from main.models.function_confirm_model.model_application import FunctionFinder
from setting.settings import CAUSE_FUNCTION_SIMILARITY_THRESHOLD, POSSIBLE_BIN_FUNCTION_TOP_N, \
    MODEL_1_TRAIN_DATA_ASM_CODE_MIN_NUM


def generate_src_codes_text(src_codes: List[str]):
    """
    保证这里和snippet_positioner的代码一致
    """
    normalized_src_codes = []
    for line in src_codes:
        if line.startswith(("+", "-")):
            line = line[1:]
        if not (normalized_line := line.strip()):
            continue
        normalized_src_codes.append(normalized_line)
    return remove_comments(" ".join(normalized_src_codes))


class VulConfirmTeam:
    def __init__(self, function_confirm_model_pth_path=r"Resources/model_weights/model_1_weights.pth",
                 snippet_positioning_model_pth_path=r"Resources/model_weights/model_2_weights_GCB.pth",
                 snippet_confirm_model_pth_path=r"Resources/model_weights/model_3_weights.pth",
                 snippet_choice_model_pth_path=r"Resources/model_weights/model_3_weights_MC.pth",
                 batch_size=16):
        # 定位漏洞函数
        logger.info("init function_finder")
        self.function_finder = FunctionFinder(model_save_path=function_confirm_model_pth_path, batch_size=batch_size)
        logger.info("init snippet_positioner")
        self.snippet_positioner = SnippetPositioner(model_save_path=snippet_positioning_model_pth_path,
                                                    batch_size=batch_size)
        logger.info("init snippet_confirmer")
        self.snippet_confirmer = SnippetConfirmer(model_save_path=snippet_confirm_model_pth_path, batch_size=batch_size)

        logger.info("init SnippetChoicer")
        self.snippet_choicer = SnippetChoicer(model_save_path=snippet_choice_model_pth_path, batch_size=batch_size)
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
                # TODO 这里要修改成直接选择更像修复前，还是修复后
                #  先定位，然后生成两个src_codes_text, 然后选择。明天做
                # 2. Model 2 定位确认漏洞片段,vul_prediction: (pred, prob, (label_0_score, label_1_score))
                vul_src_codes_text, vul_asm_codes_window_texts, vul_predictions = self.confirm_snippet(
                    cause_function,
                    possible_bin_function,
                    is_vul=True)

                for asm_codes_window_text, (pred, prob, scores) in zip(vul_asm_codes_window_texts, vul_predictions):
                    pas = PossibleAsmSnippet(vul_src_codes_text, asm_codes_window_text, pred, prob, scores=scores)
                    possible_bin_function.possible_vul_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.has_vul_snippet = True
                        possible_bin_function.confirmed_vul_snippet_count += 1
                        possible_bin_function.vul_score += scores[1]

                # 3. Model 2 定位确认补丁片段
                patch_src_codes_text, patch_asm_codes_window_texts, patch_predictions = self.confirm_snippet(
                    cause_function,
                    possible_bin_function,
                    is_vul=False)

                for asm_codes_window_text, (pred, prob, scores) in zip(vul_asm_codes_window_texts, patch_predictions):
                    # logger.info(f"pred: {pred}, prob: {prob}")
                    pas = PossibleAsmSnippet(patch_src_codes_text, asm_codes_window_text, pred, prob, scores=scores)
                    possible_bin_function.possible_patch_snippets.append(pas)
                    if pred == 1:
                        possible_bin_function.has_patch_snippet = True
                        possible_bin_function.confirmed_patch_snippet_count += 1
                        possible_bin_function.patch_score += scores[1]

                # 4. 判定是否是漏洞函数，并记录判定原因
                # 如果没有漏洞函数，判定为False
                if possible_bin_function.has_vul_snippet:
                    possible_bin_function.is_vul_function = True
                else:
                    possible_bin_function.is_vul_function = False

                # 如果有漏洞函数，则补丁更多，判定为修复
                if possible_bin_function.patch_score >= possible_bin_function.vul_score:
                    possible_bin_function.is_repaired = True
                else:
                    possible_bin_function.is_repaired = False
                possible_bin_function.judge_reason = f"possible_bin_function vul_score= {possible_bin_function.vul_score}, " \
                                                     f"possible_bin_function patch_score= {possible_bin_function.patch_score}, "
            cause_function.summary()
        vul.summary()
        logger.info(f"Confirm Done, Time cost: {round(time.perf_counter() - start_at, 2)}s")

    def new_confirm(self, binary_path, vul: Vulnerability):
        """
        新的确认方法
            1. 找到漏洞函数
            2. 找到漏洞片段
            3. 判断是否已经被修复
        """
        # 提取二进制特征
        # bin_function_features = extract_bin_feature(binary_file_abs_path)
        # ---------- 临时使用已经提取好的特征，以下是临时代码 ----------
        if "TestCases/binaries" in binary_path:
            IDA_PRO_OUTPUT_PATH = binary_path.replace("TestCases/binaries/",
                                                      "TestCases/binary_function_features/") + ".json"
        results = load_from_json_file(IDA_PRO_OUTPUT_PATH)
        # 转换成外部的数据结构
        bin_function_features: List[BinFunctionFeature] = [BinFunctionFeature.init_from_dict(data=json_item)
                                                           for json_item in results]
        # logger.info(f"{len(bin_function_features)} features extracted for {binary_file_abs_path}")
        # ---------- 以上是临时代码 ----------

        binary_analysis_info = BinaryAnalysisInfo(binary_path, len(bin_function_features))  # 分析代码
        # 筛选
        bin_function_features = [bff for bff in bin_function_features if
                                 len(bff.asm_codes) > MODEL_1_TRAIN_DATA_ASM_CODE_MIN_NUM]
        vul_analysis_info = VulAnalysisInfo(binary_analysis_info)  # 分析代码
        for cause_function in vul.cause_functions:
            cause_function_analysis_info = CauseFunctionAnalysisInfo(cause_function.function_name)  # 分析代码
            vul_analysis_info.cause_function_analysis_infos.append(cause_function_analysis_info)  # 分析代码

            # 提取源代码特征
            vul_src_function_feature: SrcFunctionFeature = extract_src_feature_for_specific_function(
                cause_function.file_path,
                cause_function.function_name)
            if not vul_src_function_feature:
                continue

            # 1. 找到漏洞函数(这里会过滤一些很短的或者很长的汇编函数)
            possible_vul_bin_functions = self.function_finder.find_bin_function(vul_src_function_feature,
                                                                                bin_function_features)

            cause_function_analysis_info.possible_bin_function_names = [  # 分析代码
                f"{pvbf.function_name}({pvbf.match_possibility})"  # 分析代码
                for pvbf in possible_vul_bin_functions]  # 分析代码

            if not possible_vul_bin_functions:
                continue

            vul_bin_function = possible_vul_bin_functions[0]
            cause_function_analysis_info.confirmed_bin_function_name = vul_bin_function.function_name  # 分析代码

        #     # 2. 定位代码片段
        #     patch = cause_function.patches[0]
        #     snippet_codes_text_before_commit, asm_codes_window_texts = self.snippet_positioner.position(
        #         vul_function_name=cause_function.function_name,
        #         src_codes=patch.snippet_codes_before_commit,
        #         asm_codes=vul_bin_function.asm_codes)
        #     print(f"\tpossible snippet num: {len(asm_codes_window_texts)}")
        #     if not asm_codes_window_texts:
        #         print(f"\tno bin snippet")
        #         continue
        #     asm_codes_window_texts = asm_codes_window_texts[:1]
        #     print(f"\tmost possible bin snippet: {asm_codes_window_texts[0]}")
        #
        #     # 3. 判断更像修复前，还是修复后
        #     snippet_codes_text_after_commit = generate_src_codes_text(patch.snippet_codes_after_commit)
        #     predictions = self.snippet_choicer.choice(asm_codes_window_texts,
        #                                               snippet_codes_text_before_commit,
        #                                               snippet_codes_text_after_commit)
        #     prediction = predictions[0]
        #     print(f"\t  vul(choice_index,score,prob): {prediction[0]}, \t  vul src code: {snippet_codes_text_before_commit}")
        #     print(f"\tpatch(choice_index,score,prob): {prediction[1]}, \tpatch src code: {snippet_codes_text_after_commit}")
        return vul_analysis_info


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
