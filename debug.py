import json

import torch
from tqdm import tqdm
from transformers import RobertaTokenizer, AutoTokenizer, RobertaForQuestionAnswering

from bintools.general.file_tool import save_to_json_file, load_from_json_file
from main.interface import DataItemForFunctionConfirmModel, FunctionFeature, DataItemForCodeSnippetPositioningModel
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
    for special_token in DataItemForCodeSnippetPositioningModel.get_special_tokens():
        tokenizer.add_tokens(special_token)
    file_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    train_data_json = load_from_json_file(file_path)
    train_data_items = [DataItemForCodeSnippetPositioningModel.init_from_dict(item) for item in train_data_json]

    token_count = []
    for data_item in tqdm(train_data_items):
        text = f"{tokenizer.cls_token}{data_item.get_question_text()}{tokenizer.sep_token}{data_item.get_context_text()}{tokenizer.sep_token}"
        tokens = tokenizer.tokenize(text)
        token_count.append({
            "function_name": data_item.function_name,
            "token_count": len(tokens),
            "src_code_count": data_item.src_length,
            "asm_code_count": data_item.asm_length,
            "answer_length": data_item.answer_length,
            "answer_start_index": data_item.answer_start_index,
            "answer_end_index": data_item.answer_end_index,
            "text": data_item.asm_length
        })
    token_count.sort(key=lambda x: x["token_count"], reverse=True)

    save_to_json_file(token_count, "TestCases/model_train/model_2/final_train_data_items/token_count.json")


def debug_get_commit_detail():
    import requests

    url = f"https://api.github.com/repos/fbb-git/yodl/commits/fd85f8c94182558ff1480d06a236d6fb927979a3"
    response = requests.get(url)
    print(response.status_code)
    if response.status_code == 200:
        save_to_json_file(response.json(),
                          r'C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer\commit_detail.json')


def find_answer_token_indices(question, context, answer_start_char, answer_end_char):
    tokenizer = AutoTokenizer.from_pretrained("deepset/roberta-base-squad2")
    encoding = tokenizer.encode_plus(
        question,
        context,
        add_special_tokens=True,
        max_length=512,
        padding='max_length',
        truncation=True,
        return_attention_mask=True,
        return_offsets_mapping=True,  # 需要offsets来计算答案位置
        return_tensors='pt',
    )
    offset_mapping = encoding["offset_mapping"].squeeze(0)  # 移除批处理维度

    # 找到第三个(0, 0)的下一个位置，因为token的顺序是：<s> question </s> </s> context </s>
    context_start_index = None
    context_end_index = None
    zero_count = 0
    for i, (start, end) in enumerate(offset_mapping):
        if start.item() == 0 and end.item() == 0:  # 非特殊token
            zero_count += 1
            if zero_count == 3:  # 找到第三个(0, 0)的位置，下一个位置就是context的开始
                context_start_index = i + 1
            if zero_count == 4:  # 找到第四个(0, 0)的位置，上一个位置就是context的结束
                context_end_index = i - 1
                break

    # 初始化答案的token位置
    answer_start_token_index, answer_end_token_index = None, None
    # 下面这两行只是为了调试
    # input_ids = encoding["input_ids"].squeeze(0)  # 移除批处理维度
    # tokens = tokenizer.convert_ids_to_tokens(input_ids)

    # 遍历每个token的偏移量
    for i, (start, end) in enumerate(offset_mapping[context_start_index:context_end_index + 1],  # 遍历context的token
                                     start=context_start_index):
        # print(i, tokens[i], start, end, answer_start_char, answer_end_char)
        # 确定答案开始token的索引
        if (answer_start_token_index is None) and (start <= answer_start_char < end):
            answer_start_token_index = i
        # 确定答案结束token的索引
        if (answer_end_token_index is None) and (start < answer_end_char <= end):
            answer_end_token_index = i

    return answer_start_token_index, answer_end_token_index


def QA_demo():
    tokenizer = AutoTokenizer.from_pretrained("deepset/roberta-base-squad2")
    model = RobertaForQuestionAnswering.from_pretrained("deepset/roberta-base-squad2")

    question, text = "Who was Jim Henson?", "Jim Henson was a nice puppet"
    target_answer_start_index, target_answer_end_index = 22, 28
    target_tokens_start_index, target_tokens_end_index = find_answer_token_indices(question, text,
                                                                                   target_answer_start_index,
                                                                                   target_answer_end_index)
    target_tokens_start_index_tensor = torch.tensor([target_tokens_start_index])
    target_tokens_end_index_tensor = torch.tensor([target_tokens_end_index])

    print(f"Question: {question}")
    print(f"Text: {text}")
    print(f"Target Answer Start Index: {target_answer_start_index}\tAnswer End Index: {target_answer_end_index}")
    print(f"Target Tokens Start Index: {target_tokens_start_index}\tAnswer Tokens End Index: {target_tokens_end_index}")
    print(f"Target Answer: {text[22:28]}\n")  # puppet

    # predict
    inputs = tokenizer(question, text, return_tensors="pt")
    with torch.no_grad():
        outputs = model(**inputs)
    predict_answer_tokens_start_index = outputs.start_logits.argmax()
    predict_answer_tokens_end_index = outputs.end_logits.argmax()
    predict_answer_tokens = inputs.input_ids[0, predict_answer_tokens_start_index: predict_answer_tokens_end_index + 1]
    predict_answer_string = tokenizer.decode(predict_answer_tokens, skip_special_tokens=True)

    print(
        f"Predict Answer Tokens Start Index: {predict_answer_tokens_start_index}\tAnswer Tokens End Index: {predict_answer_tokens_end_index}")
    print(f"Predict Answer: {predict_answer_string}")

    outputs = model(**inputs,
                    start_positions=target_tokens_start_index_tensor,
                    end_positions=target_tokens_end_index_tensor)
    loss = outputs.loss
    loss_value = round(loss.item(), 2)
    print(f"Loss: {loss_value}")


if __name__ == '__main__':
    # debug_token_length()
    # debug_get_commit_detail()
    # debug_model_2_token_length()
    QA_demo()
    # answer_start_token_index, answer_end_token_index = find_answer_token_indices("Who was Jim Henson?",
    #                                                                              "Jim Henson was a nice puppet",
    #                                                                              22,
    #                                                                              28)
    # print(answer_start_token_index, answer_end_token_index)
