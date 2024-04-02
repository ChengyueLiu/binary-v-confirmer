# # tokenizer
from collections import Counter
from random import shuffle

from bintools.general.src_tool import count_function_effective_lines


def check_tokenizer():
    from tqdm import tqdm
    from transformers import RobertaTokenizer

    from bintools.general.file_tool import load_from_json_file
    from main.interface import DataItemForFunctionConfirmModel

    model_name = 'microsoft/graphcodebert-base'
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)

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

    # 加载数据
    train_data_json = load_from_json_file("TestCases/model_train/model_1/train_data/train_data.json")
    shuffle(train_data_json)

    # 生成训练数据对象
    data_items = []
    for item in tqdm(train_data_json[:1000]):
        data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    # 检查
    min_ratio = float("inf")
    max_ratio = 0
    ratios = []
    count = 0
    for data_item in tqdm(data_items):



        text = data_item.get_train_text(tokenizer.sep_token)
        src_code, asm_code = text.split(tokenizer.sep_token)
        text_length, words_num, token_length = get_token_length(text)
        src_length, src_words_num, src_token_length = get_token_length(src_code)
        asm_length, asm_words_num, asm_token_length = get_token_length(asm_code)

        if token_length > 512:
            count += 1
            print(f"function_name： {data_item.function_name} ")
            print(f"\t{text}")
            print(f"\ttext： \t{text_length} \t{words_num} \t{token_length}")
            print(f"\tsrc： \t\t{src_length} \t{src_words_num} \t{src_token_length}")
            print(f"\tasm： \t\t{asm_length} \t{asm_words_num} \t{asm_token_length}")

        src_line_num = count_function_effective_lines(data_item.src_codes)
        asm_line_num = len(data_item.asm_codes)
        ratio = round(len(text) / token_length, 1)

        if ratio < min_ratio:
            min_ratio = ratio
        if ratio > max_ratio:
            max_ratio = ratio
        ratios.append(ratio)
    print(f"count: {count}")
    avg_ratio = round(sum(ratios) / len(ratios), 1)
    print(f"min_ratio: {min_ratio}, max_ratio: {max_ratio}, avg_ratio: {avg_ratio}")
    # 打印ratio 数量分布情况
    counter = Counter(ratios)
    print(counter.most_common(10))

def check_failed_items():
    from bintools.general.file_tool import load_from_json_file
    from bintools.general.src_tool import count_function_effective_lines
    from main.interface import DataItemForFunctionConfirmModel

    test_items = load_from_json_file("TestCases/model_train/model_1/train_data/test_data.json")
    test_item_dict = {item["id"]: item for item in test_items}
    label_0 = 0
    label_1 = 0
    failed_id_list = \
        [2, 20, 36, 40, 52, 56, 64, 76, 87, 94, 100, 104, 122, 128, 146, 150, 152, 154, 162, 170, 186, 218, 248, 250,
         262,
         280, 358, 360, 376, 388, 418, 462, 468, 476, 480, 488, 512, 513, 518, 522, 528, 542, 554, 590, 592, 616, 618,
         628,
         638, 644, 646, 658, 662, 664, 674, 698, 704, 716, 722, 724, 732, 746, 750, 768, 772, 794, 802, 816, 856, 860,
         862,
         896, 898, 912, 914, 1068, 1070, 1090, 1098, 1104, 1110, 1184, 1204, 1218, 1234, 1236, 1304, 1310, 1330, 1342,
         1346,
         1347, 1360, 1372, 1402, 1416, 1436, 1454, 1462, 1468, 1472, 1474, 1478, 1492, 1502, 1508, 1532, 1544, 1546,
         1572,
         1580, 1594, 1598, 1604, 1614, 1640, 1648, 1650, 1664, 1670, 1688, 1698, 1700, 1720, 1726, 1728, 1730, 1766,
         1780,
         1786, 1794, 1800]

    for id in failed_id_list:
        demo = DataItemForFunctionConfirmModel.init_from_dict(test_item_dict[id])
        effective_line_num = count_function_effective_lines(demo.src_codes)
        demo.normalize()
        text = demo.get_train_text("<s>")
        src_string, asm_string = text.split("<s>")
        print(demo.get_train_text("<s>"))
        print(id, demo.label,
              f"\n\t{text}\n\t{src_string.strip()}\n\t{asm_string.strip()}\n\t{demo.src_codes}\n\t{demo.asm_codes}")
        if demo.label == 0:
            label_0 += 1
        else:
            label_1 += 1
        # print(asm_strings)

    print(len(failed_id_list), label_0, label_1)


if __name__ == '__main__':
    check_tokenizer()
