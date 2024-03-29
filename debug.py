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
    [0, 121, 161, 165, 472, 638, 759, 857, 978, 1115, 1155, 1157, 1309, 1354, 1358, 1573, 1693, 1936, 1957, 1974, 2035, 2068, 2134, 2239, 2244, 2253, 2462, 2463, 2695, 2728, 2915, 3102, 3236, 3283, 3388, 3545, 3795, 3817, 3825, 3831, 3902, 4163, 4201, 4327, 4374, 4399, 4518, 4595, 4615, 4619, 4653, 4663, 4730, 4735, 5005, 5028, 5029, 5154, 5266, 5357, 5495, 5500, 5587, 5594, 5598, 5631, 5784, 5785, 5786, 5811, 5981, 6041, 6092, 6258, 6501, 6721, 6842, 6861, 6863, 6870, 6877, 6952, 6962, 7073]


for id in failed_id_list:
    demo = DataItemForFunctionConfirmModel.init_from_dict(test_item_dict[id])
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
