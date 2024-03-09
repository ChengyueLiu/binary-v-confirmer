from tqdm import tqdm
from transformers import RobertaTokenizer

from bintools.general.file_tool import save_to_json_file
from main.interface import DataItemForFunctionConfirmModel, FunctionFeature


def debug_token_length():
    function_features = FunctionFeature.init_from_json_file("TestCases/feature_extraction/function_features.json")

    # positive examples
    positive_train_data_items = [DataItemForFunctionConfirmModel.init_from_function_feature(ff, label=1) for ff in
                                 function_features]
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/graphcodebert-base')
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)
    token_count = []
    for data_item in tqdm(positive_train_data_items):
        text = data_item.get_train_text(tokenizer.sep_token)
        tokens = tokenizer.tokenize(text)

        # 检查tokens的数量
        # if len(tokens) > 512:
        #     print(data_item.function_name, len(tokens))
        token_count.append({
            "function_name": data_item.function_name,
            "token_count": len(tokens),
            "src_code_count": len(data_item.src_codes),
            "src_string_count": len(data_item.src_strings),
            "src_number_count": len(data_item.src_numbers),
            "asm_code_count": len(data_item.asm_codes),
            "bin_string_count": len(data_item.bin_strings),
            "bin_number_count": len(data_item.bin_numbers),
            "text": text
            # "asm_codes": data_item.asm_codes if len(tokens) <= 512 else None,
        })
    token_count.sort(key=lambda x: x["token_count"], reverse=True)
    save_to_json_file(token_count, "TestCases/model_train/model_1/train_data/token_count.json")


if __name__ == '__main__':
    debug_token_length()
