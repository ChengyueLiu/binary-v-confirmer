# # tokenizer
# from tqdm import tqdm
# from transformers import RobertaTokenizer
#
# from bintools.general.file_tool import load_from_json_file
# from main.interface import DataItemForFunctionConfirmModel
#
# model_name = 'microsoft/graphcodebert-base'
# tokenizer = RobertaTokenizer.from_pretrained(model_name)
# for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
#     tokenizer.add_tokens(special_token)
#
# train_data_json = load_from_json_file("TestCases/model_train/model_1/train_data/val_data.json")
# data_items = []
# for item in train_data_json:
#     data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
#     data_item.normalize()
#     data_items.append(data_item)
#
#
# def get_token_length(text):
#     encoding = tokenizer.encode_plus(
#         text,
#         add_special_tokens=True,
#         # max_length=512,
#         # padding='max_length',
#         # truncation=True,
#         return_attention_mask=True,
#         return_tensors='pt',
#     )
#     # 输出token长度
#     token_length = len(encoding['input_ids'][0])
#     text_length = len(text)
#     words_num = len(text.split())
#     return text_length, words_num, token_length
#
#
# for data_item in tqdm(data_items[:100]):
#     text = data_item.get_train_text(tokenizer.sep_token)
#
#     src_code, asm_code = text.split(tokenizer.sep_token)
#     text_length, words_num, token_length = get_token_length(text)
#     src_length, src_words_num, src_token_length = get_token_length(src_code)
#     asm_length, asm_words_num, asm_token_length = get_token_length(asm_code)
#     print(f"{data_item.id}, src: {src_length}, {src_words_num}, {src_token_length}, {round(src_token_length/src_words_num)}, asm: {asm_length}, {asm_words_num}, {asm_token_length}, {round(asm_token_length/asm_words_num)}, total: {text_length}, {words_num}, {token_length}, {round(token_length/words_num)}")
from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetPositioningModel

from bintools.general.file_tool import load_from_json_file
from bintools.general.src_tool import count_function_effective_lines
from main.interface import DataItemForFunctionConfirmModel

test_items = load_from_json_file("TestCases/model_train/model_1/train_data/val_data.json")
test_item_dict = {item["id"]: item for item in test_items}
label_0 = 0
label_1 = 0
failed_id_list = \
    [0, 121, 165, 373, 461, 554, 626, 638, 746, 747, 757, 759, 805, 849, 857, 968, 1001, 1005, 1023, 1073, 1087, 1111, 1115, 1225, 1309, 1417, 1430, 1573, 1691, 1693, 1726, 1804, 1811, 1879, 1936, 1947, 1974, 1975, 1978, 2023, 2035, 2049, 2134, 2197, 2237, 2239, 2244, 2386, 2462, 2571, 2692, 2695, 2713, 2728, 2912, 2915, 2942, 3023, 3034, 3102, 3105, 3170, 3173, 3177, 3223, 3234, 3278, 3285, 3300, 3320, 3349, 3388, 3431, 3504, 3505, 3509, 3513, 3629, 3639, 3748, 3806, 3817, 3831, 3894, 3949, 3993, 4010, 4062, 4092, 4110, 4163, 4168, 4179, 4201, 4256, 4327, 4374, 4399, 4403, 4417, 4430, 4497, 4547, 4584, 4595, 4606, 4609, 4653, 4664, 4865, 4905, 4927, 5005, 5119, 5203, 5210, 5231, 5291, 5495, 5500, 5577, 5588, 5594, 5598, 5607, 5621, 5786, 5810, 5811, 5815, 5981, 6038, 6073, 6092, 6106, 6135, 6227, 6258, 6335, 6488, 6666, 6686, 6755, 6841, 6842, 6853, 6861, 6870, 6952, 7007, 7022, 7073]


for id in failed_id_list:
    demo = DataItemForFunctionConfirmModel.init_from_dict(test_item_dict[7073])
    effective_line_num = count_function_effective_lines(demo.src_codes)
    demo.normalize()
    src_string, asm_string = demo.get_train_text("<s>").split("<s>")
    print(id, demo.label, f"\n\t{src_string.strip()}\n\t{asm_string.strip()}\n\t{demo.src_codes}\n\t{demo.asm_codes}")
    if demo.label == 0:
        label_0 += 1
    else:
        label_1 += 1
    # print(asm_strings)

print(len(failed_id_list), label_0, label_1)

#
# test_items = load_from_json_file("TestCases/model_train/model_2/final_train_data_items/test_data.json")
# for item in test_items:
#     demo = DataItemForCodeSnippetPositioningModel.init_from_dict(item)
#     demo.normalize()
#     print(demo.id, f"\n\tQ：{demo.get_question_text()}\n\tC:{demo.get_context_text()}\n\tA:{demo.get_answer_text()}")
