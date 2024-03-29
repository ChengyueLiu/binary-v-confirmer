# tokenizer
from tqdm import tqdm
from transformers import RobertaTokenizer

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel

model_name = 'microsoft/graphcodebert-base'
tokenizer = RobertaTokenizer.from_pretrained(model_name)
for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
    tokenizer.add_tokens(special_token)

train_data_json = load_from_json_file("TestCases/model_train/model_1/train_data/val_data.json")
data_items = []
for item in train_data_json:
    data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
    data_item.normalize()
    data_items.append(data_item)


def get_token_length(text):
    encoding = tokenizer.encode_plus(
        text,
        add_special_tokens=True,
        # max_length=512,
        # padding='max_length',
        # truncation=True,
        return_attention_mask=True,
        return_tensors='pt',
    )
    # 输出token长度
    token_length = len(encoding['input_ids'][0])
    text_length = len(text)
    words_num = len(text.split())
    return text_length, words_num, token_length


for data_item in tqdm(data_items[:100]):
    text = data_item.get_train_text(tokenizer.sep_token)

    src_code, asm_code = text.split(tokenizer.sep_token)
    text_length, words_num, token_length = get_token_length(text)
    src_length, src_words_num, src_token_length = get_token_length(src_code)
    asm_length, asm_words_num, asm_token_length = get_token_length(asm_code)
    print(f"{data_item.id}, src: {src_length}, {src_words_num}, {src_token_length}, {round(src_token_length/src_words_num)}, asm: {asm_length}, {asm_words_num}, {asm_token_length}, {round(asm_token_length/asm_words_num)}, total: {text_length}, {words_num}, {token_length}, {round(token_length/words_num)}")

# from bintools.general.file_tool import load_from_json_file
# from bintools.general.src_tool import count_function_effective_lines
# from main.interface import DataItemForFunctionConfirmModel
#
# test_items = load_from_json_file("TestCases/model_train/model_1/train_data/val_data.json")
# test_item_dict = {item["id"]: item for item in test_items}
# label_0 = 0
# label_1 = 0
# failed_id_list = \
#     [10, 77, 121, 472, 572, 747, 759, 857, 1100, 1111, 1155, 1309, 1320, 1354, 1430, 1573, 1584, 1606, 1650, 1691, 1936, 1947, 1974, 2035, 2233, 2239, 2244, 2276, 2497, 2695, 2728, 2893, 2915, 3069, 3102, 3168, 3234, 3283, 3388, 3432, 3509, 3718, 3784, 3817, 3894, 3993, 4092, 4110, 4168, 4399, 4411, 4417, 4509, 4519, 4576, 4595, 4615, 4653, 4730, 5005, 5038, 5154, 5291, 5495, 5508, 5594, 5621, 5670, 5731, 5795, 5811, 5981, 6006, 6092, 6237, 6258, 6501, 6666, 6677, 6754, 6787, 6842, 6861, 6863, 6952, 7073]
#
#
# for id in failed_id_list:
#     demo = DataItemForFunctionConfirmModel.init_from_dict(test_item_dict[id])
#     effective_line_num = count_function_effective_lines(demo.src_codes)
#     demo.normalize()
#     asm_strings = demo.get_train_text().split("[ASM_CODE]")[1]
#     print(demo.label, demo.get_train_text())
#     if demo.label == 0:
#         label_0 += 1
#     else:
#         label_1 += 1
#     # print(asm_strings)
#
# print(len(failed_id_list), label_0, label_1)
