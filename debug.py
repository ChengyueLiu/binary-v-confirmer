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
from rapidfuzz import process, fuzz

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
    [12, 25, 64, 85, 187, 273, 336, 416, 423, 456, 549, 562, 569, 598, 695, 700, 704, 720, 782, 817, 898, 932, 981, 1040, 1041, 1082, 1095, 1290, 1336, 1353, 1426, 1435, 1450, 1454, 1544, 1565, 1577, 1606, 1613, 1616, 1645, 1682, 1712, 1716, 1789, 1797]


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

# def find_top_n_similar(target, strings, n=5):
#     # 使用rapidfuzz的process.extract方法找到最相似的N个字符串
#     top_n_similar = process.extract(target, strings, scorer=fuzz.ratio, limit=n)
#     return top_n_similar
#
# # 示例字符串列表
# strings = ["apple", "apples", "apricot", "banana", "cherry", "blueberry", "blackberry", "strawberry", "raspberry"]
# # 目标字符串
# target = "apple"
#
# # 找出最相似的5个字符串
# top_similar = process.extract(target, strings, scorer=fuzz.ratio, limit=5)
# for match in top_similar:
#     print(match)