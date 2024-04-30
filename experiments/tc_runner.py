from typing import List

from loguru import logger

from experiments.model_input_manager import filter_and_generate_function_confirm_model_input, \
    generate_snippet_locate_model_input, generate_snippet_choice_model_input
from experiments.experiment_analysis import Analysis
from experiments.extractor_runner import extract_asm_functions
from main.interface import DataItemForFunctionConfirmModel
from main.models.code_snippet_confirm_model_multi_choice.new_model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.new_model_application import SnippetPositioner
from main.models.function_confirm_model.new_model_application import FunctionConfirmer
from main.tc_models import VulConfirmTC, VulFunction, TestBin


class TCRunner:
    def __init__(self, function_confirm_model_pth, snippet_position_model_pth, snippet_choice_model_pth):
        logger.info(f"init model...")
        self.confirm_model = FunctionConfirmer(model_save_path=function_confirm_model_pth, batch_size=128)
        self.locate_model = SnippetPositioner(model_save_path=snippet_position_model_pth)
        self.choice_model = SnippetChoicer(model_save_path=snippet_choice_model_pth)
        logger.info(f"model init success")

        self.analysis = Analysis()

    def run(self, tc: VulConfirmTC, asm_functions_cache):
        # step 1: prepare data
        vul_function_dict = {vf.get_function_name(): vf for vf in tc.vul_functions}
        asm_function_dict = extract_asm_functions(tc.test_bin, asm_functions_cache)

        # step 2: filter
        filtered_data_items = filter_and_generate_function_confirm_model_input(list(vul_function_dict.values()),
                                                                               asm_function_dict)
        # step 3: confirm functions
        confirmed_data_items = self._confirm_functions(filtered_data_items)

        # step 4: locate vul snippet
        locate_results = self._locate_patch(vul_function_dict, confirmed_data_items)

        # step 5: check patch
        is_fixed = self._check_patch(locate_results)

        # step 6: summary result
        self._summary_result(tc, filtered_data_items, confirmed_data_items, locate_results, is_fixed)

    def _confirm_functions(self, filtered_data_items) -> List[DataItemForFunctionConfirmModel]:
        predictions = self.confirm_model.confirm(filtered_data_items)
        confirmed_data_items = []
        for data_item, (pred, prob) in zip(filtered_data_items, predictions):
            if pred == 1 and prob > 0.99:
                confirmed_data_items.append(data_item)
        logger.info(f"confirm: {len(filtered_data_items)} ---> {len(confirmed_data_items)}")
        return confirmed_data_items

    def _locate_patch(self, vul_function_dict, confirmed_data_items: List[DataItemForFunctionConfirmModel]):
        locate_results = []
        for confirmed_data_item in confirmed_data_items:
            vul_function_name = confirmed_data_item.function_name
            vul_function: VulFunction = vul_function_dict[vul_function_name]

            for i, patch in enumerate(vul_function.patches, 1):
                # generate model input
                locate_model_input_data_items = generate_snippet_locate_model_input(vul_function_name,
                                                                                    confirmed_data_item.bin_function_name,
                                                                                    patch,
                                                                                    confirmed_data_item.asm_codes)
                # predict
                predictions = self.locate_model.locate(locate_model_input_data_items)

                # find most possible result
                most_prob = 0
                most_index = 0
                most_result = None
                for j, (pred, prob) in enumerate(predictions):
                    if prob < 0.95:
                        continue
                    if prob > most_prob:
                        most_prob = prob
                        most_index = j
                        most_result = (vul_function_name,
                                       patch,
                                       confirmed_data_item.bin_function_name,
                                       locate_model_input_data_items[j].asm_codes)

                # if find result, print log
                if most_result:
                    log_info = f"locate: {vul_function_name} patch {i} in {confirmed_data_item.bin_function_name} window {most_index}, asm_codes_length: {len(most_result[-1])}, prob: {most_prob}"
                    logger.debug(log_info)
                    locate_results.append(most_result)
        if not locate_results:
            logger.debug(f"no patch located")
        return locate_results

    def _check_patch(self, locate_results):
        choice_model_input_data_items = generate_snippet_choice_model_input(locate_results)
        predictions = self.choice_model.choice(choice_model_input_data_items)
        vul_prob = 0
        fix_prob = 0
        for (_, option_0_prob), (_, option_1_prob) in predictions:
            vul_prob += option_0_prob
            fix_prob += option_1_prob
        is_fixed = fix_prob > vul_prob
        logger.debug(f"is fixed: {is_fixed}")
        return is_fixed

    def _summary_result(self, tc, filtered_data_items, confirmed_data_items, locate_results, is_fixed):
        logger.success(f"summary result:")
        for function in tc.vul_functions:
            logger.success(f"summary vul function: {function.get_function_name()}")
            # filter
            find_flag = False
            for data_item in filtered_data_items:
                if function.get_function_name() == data_item.bin_function_name:
                    logger.success(f"\tfilter success: {function.get_function_name()}!")
                    find_flag = True
                    break
            if not find_flag:
                logger.warning(f"\tfilter failed: {function.get_function_name()}!")

            # confirm
            print()
            if confirmed_data_items:
                for data_item in confirmed_data_items:
                    if data_item.function_name == data_item.bin_function_name:
                        logger.success(f"\tconfirm TP: {data_item.bin_function_name}")
                    else:
                        logger.warning(f"\tconfirm FP: {data_item.bin_function_name}")
            else:
                logger.warning(f"\tno functions confirmed!")
                continue

            # locate
            print()
            if locate_results:
                for vul_function_name, patch, bin_function_name, asm_codes in locate_results:
                    if vul_function_name == bin_function_name:
                        logger.success(f"\tlocate TP: {vul_function_name}")
                    else:
                        logger.warning(f"\tlocate FP: {vul_function_name}")
            else:
                logger.warning(f"\tno patch located!")
                continue

            # check
            print()
            if is_fixed == tc.ground_truth.is_fixed:
                logger.success(f"check Success: {tc.ground_truth.is_fixed} ---> {is_fixed}")
            else:
                logger.error(f"check Failed: {tc.ground_truth.is_fixed} ---> {is_fixed}")
