# # tokenizer
import copy
from collections import Counter
from random import shuffle

from transformers import BigBirdTokenizer

from bintools.general.normalize import normalize_src_lines
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

    test_items = load_from_json_file("TestCases/model_train/model_1/train_data/val_data.json")
    test_item_dict = {item["id"]: item for item in test_items}
    label_0 = 0
    label_1 = 0
    failed_id_list = \
        [97, 268, 300, 388, 429, 519, 616, 742, 793, 818, 859, 1044, 1052, 1063, 1099, 1190, 1243, 1272, 1278, 1280,
         1556, 1697, 1747, 1812, 1867, 2044, 2310, 2526, 2527, 2561, 2730, 2768, 2820, 2866, 2897, 3202, 3260, 3529,
         3605, 3607, 3616, 3728, 3809, 4020, 4319, 4359, 4705, 4721, 4775, 4835, 4870, 4872, 4907, 5100, 5101, 5227,
         5228, 5235, 5260, 5516, 5535, 5590, 5601, 5617, 5645, 5816, 5883, 6030, 6088, 6105, 6364, 6405, 6444, 6459,
         6477, 6479, 6557, 6632, 6673, 6689, 6817, 6988, 7075, 7173, 7220, 7284, 7323, 7361, 7417, 7430, 7523, 7652,
         7709, 7784, 7894, 8100, 8164, 8220, 8321, 8418, 8648, 9043, 9070, 9163, 9177, 9308, 9894, 9981, 10209, 10220,
         10233, 10319, 10387, 10559, 10587, 10594, 10625, 10685, 10744, 10958, 11038, 11128, 11164, 11205, 11259, 11290,
         11291, 11303, 11450, 11565, 11800, 11970, 12018, 12078, 12136, 12193, 12213, 12427, 12434, 12585, 12678, 12743,
         12776, 12800, 12928, 12971, 13030, 13095, 13175, 13257, 13275, 13359, 13393, 13455, 13467, 13614, 13625, 13802,
         13805, 13908, 13921, 14065, 14176, 14370, 14511, 14564, 14571, 14610, 14703, 14730, 14742, 14756, 14900, 14949,
         14959, 14999, 15034, 15161, 15287, 15419, 15488, 15502, 15515, 15540, 15548, 15587, 15698, 15718, 15787, 15812,
         16065, 16311, 16427, 16478, 16482, 16552, 16573, 16805, 16829, 16836, 17126, 17195, 17242, 17285, 17330, 17372,
         17448, 17467, 17548, 17586, 17645, 17741, 17944, 17994, 18056, 18077, 18239, 18263, 18407, 18516]

    for id in failed_id_list:
        demo = DataItemForFunctionConfirmModel.init_from_dict(test_item_dict[id])
        effective_line_num = count_function_effective_lines(demo.src_codes)
        src_codes = copy.copy(demo.src_codes)
        asm_codes = copy.copy(demo.asm_codes)
        demo.normalize()
        text = demo.get_train_text("<s>")
        src_text, asm_text = text.split("<s>")
        print(demo.get_train_text("<s>"))
        print(id, demo.label,demo.function_name,
              f"\n\t{src_text}"
              f"\n\t{src_codes}"
              f"\n\t{asm_text}"
              f"\n\t{asm_codes}")
        if demo.label == 0:
            label_0 += 1
        else:
            label_1 += 1
        # print(asm_strings)

    print(len(test_items),len(failed_id_list), label_0, label_1)

def check_normaliize():
    src_codes = [
            "  /* We have already examined parent j and we know parent i",
            "   * and parent j are the same, so reuse the combined result",
            "   * of parent j for parent i.",
            "   */",
            "  unsigned long lno, imask, jmask;",
            "  imask = (1UL << i);",
            "  jmask = (1UL << j);",
            "",
            "  for (lno = 0; lno <= cnt; lno++) {",
            "    struct lline *ll = sline->lost;",
            "    sline->p_lno[i] = sline->p_lno[j];",
            "    while (ll) {",
            "      if (ll->parent_map & jmask)",
            "        ll->parent_map |= imask;",
            "      ll = ll->next;",
            "    }",
            "    if (sline->flag & jmask)",
            "      sline->flag |= imask;",
            "    sline++;",
            "  }",
            "  /* the overall size of the file (sline[cnt]) */",
            "  sline->p_lno[i] = sline->p_lno[j];",
            "}"
        ]
    for line in normalize_src_lines(src_codes):
        print(line)

if __name__ == '__main__':
    # check_tokenizer()

    # check_failed_items()
    check_normaliize()