import json

from tqdm import tqdm
from transformers import RobertaTokenizer

from bintools.general.file_tool import save_to_json_file
from main.interface import DataItemForFunctionConfirmModel, FunctionFeature
from main.models.code_snippet_positioning_model.dataset_and_data_provider import create_dataset


def debug_model_1_token_length():
    function_features = FunctionFeature.init_from_json_file(
        "TestCases/feature_extraction/openssl_feature/function_features.json")

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
    save_to_json_file(token_count, "TestCases/model_train/model_1/train_data/openssl/token_count.json")


def debug_model_2_token_length():
    tokenizer = RobertaTokenizer.from_pretrained('microsoft/graphcodebert-base')
    dataset = create_dataset("TestCases/model_train/model_2/final_train_data_items/train_data.json", tokenizer, 512)



def debug_get_commit_detail():
    import requests

    url = f"https://api.github.com/repos/fbb-git/yodl/commits/fd85f8c94182558ff1480d06a236d6fb927979a3"
    response = requests.get(url)
    print(response.status_code)
    if response.status_code == 200:
        save_to_json_file(response.json(),
                          r'C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer\commit_detail.json')


if __name__ == '__main__':
    # debug_token_length()
    debug_get_commit_detail()
