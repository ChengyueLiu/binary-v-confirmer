from loguru import logger

from main.models.code_snippet_confirm_model_multi_choice.new_model_application import SnippetChoicer
from main.models.code_snippet_positioning_model.new_model_application import SnippetPositioner
from main.models.function_confirm_model.new_model_application import FunctionConfirmer


def init_models(model_2_save_path, model_3_save_path, model_save_path):
    logger.info(f"init model...")
    confirm_model = FunctionConfirmer(model_save_path=model_save_path, batch_size=128)
    locate_model = SnippetPositioner(model_save_path=model_2_save_path)
    choice_model = SnippetChoicer(model_save_path=model_3_save_path)
    logger.success(f"model init success")
    return confirm_model, choice_model, locate_model
