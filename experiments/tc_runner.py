from typing import List

from loguru import logger

from experiments.model_input_manager import filter_and_generate_function_confirm_model_input, \
    generate_snippet_locate_model_input, generate_snippet_choice_model_input
from experiments.experiment_analysis import Analysis
from experiments.extractor_runner import extract_asm_functions
from main.interface import DataItemForFunctionConfirmModel, DataItemForCodeSnippetPositioningModel
from main.models.code_snippet_confirm_model_multi_choice.new_model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.new_model_application import SnippetPositioner
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin


class TCRunner:
    def __init__(self, function_confirm_model_pth, snippet_position_model_pth, snippet_choice_model_pth):
        self.confirm_threshold = 0.99
        self.locate_threshold = 0.5

        logger.info(f"init model...")
        self.confirm_model = FunctionConfirmer(model_save_path=function_confirm_model_pth, batch_size=128)
        self.locate_model = SnippetPositioner(model_save_path=snippet_position_model_pth)
        self.choice_model = SnippetChoicer(model_save_path=snippet_choice_model_pth)
        logger.info(f"model init success")

        self.analysis = Analysis()
        self.csv_data = []

    def run(self, tc: VulConfirmTC, asm_functions_cache):
        self.csv_data.append(f"{tc.has_vul_function()},{tc.has_vul()}")

        # step 1: prepare data
        vul_function_dict = {vf.get_function_name(): vf for vf in tc.vul_functions}
        asm_function_dict = extract_asm_functions(tc.test_bin, asm_functions_cache)

        # step 2: filter
        filtered_data_items = filter_and_generate_function_confirm_model_input(list(vul_function_dict.values()),
                                                                               asm_function_dict)
        # step 3: confirm functions
        confirmed_data_items = self._confirm_functions(filtered_data_items)

        # step 4: locate vul snippet
        locate_results = self._locate_vul_snippet(vul_function_dict, confirmed_data_items)

        # step 5: check patch
        is_fixed = self._check_patch(locate_results)

        # step 6: summary result
        self._print_log(tc, filtered_data_items, confirmed_data_items, locate_results, is_fixed)

        # step 7: analysis
        has_vul = self.analyze(tc, locate_results, is_fixed)

        return has_vul

    def _confirm_functions(self, filtered_data_items) -> List[DataItemForFunctionConfirmModel]:
        predictions = self.confirm_model.confirm(filtered_data_items)
        confirmed_data_items = []
        for data_item, (pred, prob) in zip(filtered_data_items, predictions):
            if pred == 1 and prob > self.confirm_threshold:
                data_item.prob = prob
                confirmed_data_items.append(data_item)
                logger.debug(f"confirm: {data_item.function_name} ---> {data_item.bin_function_name}, prob: {prob}")
        logger.info(f"confirm: {len(filtered_data_items)} ---> {len(confirmed_data_items)}")
        return confirmed_data_items

    def _locate_vul_snippet(self, vul_function_dict, confirmed_data_items: List[DataItemForFunctionConfirmModel]):
        # group by vul function
        group_dict = {}
        for data_item in confirmed_data_items:
            vul_function_name = data_item.function_name
            if vul_function_name not in group_dict:
                group_dict[vul_function_name] = []
            group_dict[vul_function_name].append(data_item)

        # find most possible patch location
        locate_results = []
        for confirmed_data_items in group_dict.values():
            most_vul_function_name = None
            most_patch_index = 0
            most_bin_function_name = None
            most_window_index = 0
            most_result = None
            most_pred = None
            most_prob = 0
            for confirmed_data_item in confirmed_data_items:
                vul_function_name = confirmed_data_item.function_name
                vul_function: VulFunction = vul_function_dict[vul_function_name]

                for i, patch in enumerate(vul_function.patches, 1):
                    locate_part = patch.vul_snippet_codes
                    # locate_part = patch.vul_snippet_codes[3:]
                    # locate_part = patch.fixed_snippet_codes[3:-3]
                    locate_model_input_data_items: List[
                        DataItemForCodeSnippetPositioningModel] = generate_snippet_locate_model_input(vul_function_name,
                                                                                                      confirmed_data_item.bin_function_name,
                                                                                                      locate_part,
                                                                                                      confirmed_data_item.asm_codes)
                    # predict
                    predictions = self.locate_model.locate(locate_model_input_data_items)

                    # find most possible result
                    for j, (data_item, (pred, prob)) in enumerate(zip(locate_model_input_data_items, predictions)):
                        if prob < self.locate_threshold:
                            # logger.warning(
                            #     f"locate failed: {vul_function_name} patch {i} in {confirmed_data_item.bin_function_name} window {j}, asm_codes_length: {len(pred)}, prob: {prob}")
                            continue
                        else:
                            logger.info(
                                f"possible: {vul_function_name} patch {i} in {confirmed_data_item.bin_function_name} window {j}, asm_codes_length: {len(pred)}, prob: {prob}, pred: {pred}")

                        # if True:
                        if prob > most_prob:
                            most_vul_function_name = vul_function_name
                            most_patch_index = i
                            most_bin_function_name = confirmed_data_item.bin_function_name
                            most_window_index = j
                            most_pred = pred
                            most_prob = prob
                            most_result = (vul_function_name,
                                           patch,
                                           confirmed_data_item.bin_function_name,
                                           locate_model_input_data_items[j].asm_codes,
                                           pred,
                                           prob)
                        else:
                            if vul_function_name == confirmed_data_item.bin_function_name:
                                pass
                                # logger.warning(
                                #     f"locate failed: {vul_function_name} patch {i} in {confirmed_data_item.bin_function_name} window {j}, asm_codes_length: {len(pred)}, prob: {prob}")

            # if find result, print log
            if most_result:
                log_info = f"locate: {most_vul_function_name} patch {most_patch_index} in {most_bin_function_name} window {most_window_index}, asm_codes_length: {len(most_pred)}, prob: {most_prob}"
                logger.info(log_info)
                locate_results.append(most_result)

        if not locate_results:
            logger.debug(f"no patch located")
        return locate_results

    def _check_patch(self, locate_results):
        choice_model_input_data_items, diff_nums = generate_snippet_choice_model_input(locate_results)
        predictions = self.choice_model.choice(choice_model_input_data_items)
        vul_prob = 0
        fix_prob = 0

        vul_score = 0
        fix_score = 0
        for ((choice, option_0_score, option_0_prob), (choice, option_1_score, option_1_prob)), diff_num in zip(
                predictions, diff_nums):
            diff_num = 0 if diff_num < 0 else diff_num
            # if diff_num < 4:
            #     option_1_score -= (diff_num * 1.4)
            # else:
            #     option_1_score -= (diff_num * 2.1)
            logger.info(
                f"diff_num: {diff_num}, choice: vul_score: {option_0_score}, fix_score: {option_1_score}, vul_prob: {option_0_prob}, fix_prob: {option_1_prob}")

            vul_prob += option_0_prob
            fix_prob += option_1_prob
            vul_score += option_0_score
            fix_score += option_1_score
            self.csv_data[-1] = (f"{self.csv_data[-1]},{diff_num},{vul_score},{fix_score}")

        if vul_score > fix_score:
            is_fixed = False
        elif vul_score < fix_score:
            is_fixed = True
        else:
            is_fixed = None
        logger.info(
            f"is fixed: {is_fixed}, vul_score: {vul_score}, fix_score: {fix_score}, vul_prob: {vul_prob}, fix_prob: {fix_prob}")

        return is_fixed

    def _print_log(self, tc, filtered_data_items, confirmed_data_items, locate_results, is_fixed):
        logger.success(f"summary result:")
        has_vul_function = False

        filter_find_flag = False
        model_1_find_flag = False
        model_1_2_find_flag = False
        model_1_2_fp_flag = False
        model_3_find_flag = False
        for function in tc.vul_functions:
            # filter
            find_flag = False
            for data_item in filtered_data_items:
                if function.get_function_name() == data_item.bin_function_name:
                    logger.success(f"\t\tfilter success: {function.get_function_name()}!")
                    find_flag = True
                    filter_find_flag = True
                    break
            if not find_flag:
                logger.warning(f"\t\tfilter failed: {function.get_function_name()}!")

        # confirm
        print()
        if confirmed_data_items:
            for data_item in confirmed_data_items:
                if data_item.function_name == data_item.bin_function_name:
                    logger.success(
                        f"\t\tconfirm TP: {data_item.function_name} ---> {data_item.bin_function_name}")
                    model_1_find_flag = True
                else:
                    logger.warning(
                        f"\t\tconfirm FP: {data_item.function_name} ---> {data_item.bin_function_name}")
        else:
            logger.warning(f"\t\tno functions confirmed!")

        # locate
        print()
        if locate_results:
            for vul_function_name, patch, bin_function_name, asm_codes, pred, prob in locate_results:
                if vul_function_name == bin_function_name:
                    logger.success(f"\t\tlocate TP: {vul_function_name} ---> {bin_function_name} {prob}")
                    model_1_2_find_flag = True
                else:
                    logger.warning(f"\t\tlocate FP: {vul_function_name} ---> {bin_function_name} {prob}")
                    model_1_2_fp_flag = True
            has_vul_function = True
        else:
            logger.warning(f"\t\tno patch located!")

        # precisely confirmed
        print()
        precisely_find_flag = model_1_2_find_flag and (not model_1_2_fp_flag)
        if precisely_find_flag:
            logger.success(f"\t\tprecisely confirmed: {precisely_find_flag}")
        else:
            logger.warning(f"\t\tprecisely confirmed: {precisely_find_flag}")

        # check
        print()
        if is_fixed == tc.ground_truth.is_fixed:
            logger.success(f"\t\tfix check: {tc.ground_truth.is_fixed} ---> {is_fixed}")
            model_3_find_flag = True
        else:
            logger.warning(f"\t\tfix check: {tc.ground_truth.is_fixed} ---> {is_fixed}")

        if not filter_find_flag:
            self.analysis.over_filter_count += 1

        if model_1_find_flag:
            self.analysis.model_1_find_count += 1

        if model_1_2_find_flag:
            self.analysis.model_1_2_find_count += 1
            if precisely_find_flag:
                self.analysis.model_1_2_precisely_find_count += 1

        if model_3_find_flag:
            self.analysis.model_3_find_count += 1
        print(filter_find_flag, model_1_find_flag, model_1_2_find_flag, precisely_find_flag, model_3_find_flag)

        # final result
        has_vul = has_vul_function and not is_fixed
        if has_vul == tc.has_vul():
            logger.success(f"ground truth: {tc.has_vul_function()} {tc.ground_truth.is_fixed}")
            logger.success(f"      result: {has_vul_function} {is_fixed}")
        else:
            logger.error(f"ground truth: {tc.has_vul_function()} {tc.ground_truth.is_fixed}")
            logger.error(f"      result: {has_vul_function} {is_fixed}")

    def analyze(self, tc, locate_results, is_fixed):
        has_vul_function = bool(locate_results)
        has_vul = False
        if has_vul_function and not is_fixed:
            has_vul = True

        if tc.has_vul():
            if has_vul:
                self.analysis.tp += 1
            else:
                self.analysis.fn += 1
        else:
            if has_vul:
                self.analysis.fp += 1
            else:
                self.analysis.tn += 1
