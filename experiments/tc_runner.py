from typing import List

from loguru import logger

from experiments.BinVC import filter_and_generate_function_confirm_model_input
from experiments.experiment_analysis import Analysis
from experiments.extractor_runner import extract_asm_functions
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

        # tmp
        self.tc = None
        self.asm_functions_cache = None

    def run(self, tc: VulConfirmTC, asm_functions_cache):
        self.tc = tc
        self.asm_functions_cache = asm_functions_cache

        # step 1: prepare data
        vul_functions, asm_function_dict = self._prepare_data()

        # step 2: filter functions
        data_items = filter_and_generate_function_confirm_model_input(asm_function_dict, vul_functions)

        # step 3: run function confirm model
        predictions = self.confirm_model.confirm(data_items)

        # run snippet position model

        # run snippet choice model

    def _prepare_data(self):
        vul_functions: List[VulFunction] = self.tc.vul_functions
        asm_function_dict = extract_asm_functions(self.tc.test_bin, self.asm_functions_cache)
        return vul_functions, asm_function_dict
