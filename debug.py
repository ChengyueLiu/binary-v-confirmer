# # tokenizer
from collections import Counter
from random import shuffle

from transformers import BigBirdTokenizer

from bintools.general.src_tool import count_function_effective_lines


def check_tokenizer():
    from tqdm import tqdm
    from transformers import RobertaTokenizer

    from bintools.general.file_tool import load_from_json_file
    from main.interface import DataItemForFunctionConfirmModel

    tokenizer = BigBirdTokenizer.from_pretrained('google/bigbird-roberta-base')
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)
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
        [62, 97, 213, 228, 300, 354, 429, 464, 498, 519, 531, 623, 690, 705, 818, 1016, 1099, 1272, 1402, 1812, 1840, 1867, 1919, 1923, 1935, 1964, 2229, 2310, 2347, 2453, 2494, 2526, 2527, 2625, 2730, 2768, 2769, 2794, 2820, 2861, 2897, 3025, 3260, 3314, 3411, 3607, 3676, 3728, 3737, 3784, 4162, 4195, 4196, 4319, 4414, 4615, 4721, 4835, 4872, 4933, 5101, 5111, 5228, 5235, 5260, 5307, 5447, 5535, 5550, 5567, 5590, 5617, 5694, 5868, 5883, 6030, 6088, 6364, 6376, 6444, 6459, 6470, 6550, 6552, 6673, 6689, 6764, 6817, 6911, 7075, 7151, 7323, 7361, 7417, 7523, 7620, 7652, 7709, 7849, 7943, 8003, 8100, 8164, 8220, 8321, 8423, 8489, 8685, 8759, 9043, 9046, 9070, 9231, 9394, 9401, 9586, 9590, 9601, 9729, 9752, 9778, 9831, 9837, 9894, 9981, 10012, 10113, 10204, 10209, 10233, 10241, 10303, 10387, 10559, 10594, 10625, 10693, 10744, 10820, 10852, 10891, 10958, 11038, 11042, 11048, 11058, 11128, 11205, 11217, 11259, 11290, 11326, 11351, 11371, 11384, 11450, 11503, 11541, 11612, 11636, 11682, 11727, 11800, 11817, 11956, 11968, 12018, 12078, 12136, 12182, 12193, 12231, 12493, 12514, 12530, 12678, 12743, 12786, 12800, 12870, 12908, 12971, 13095, 13359, 13418, 13455, 13467, 13473, 13494, 13497, 13506, 13560, 13614, 13672, 13773, 13805, 13908, 14087, 14176, 14224, 14291, 14344, 14470, 14511, 14558, 14571, 14604, 14729, 14742, 14756, 14781, 14847, 14900, 14949, 14959, 14992, 15005, 15026, 15059, 15147, 15161, 15268, 15366, 15419, 15459, 15501, 15515, 15548, 15578, 15587, 15664, 15699, 15718, 15941, 16011, 16098, 16105, 16161, 16227, 16311, 16381, 16427, 16482, 16552, 16573, 16585, 16604, 16641, 16684, 16763, 16779, 16805, 16836, 17106, 17126, 17130, 17195, 17221, 17260, 17285, 17352, 17372, 17403, 17443, 17445, 17538, 17620, 17753, 17915, 17937, 17994, 18031, 18077, 18134, 18201, 18386, 18407, 18412, 18505, 18516, 18550]

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
    # check_tokenizer()

    check_failed_items()