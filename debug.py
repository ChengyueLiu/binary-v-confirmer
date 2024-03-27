from transformers import RobertaTokenizer

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel
from main.models.function_confirm_model.model_training import init_train
from tqdm import tqdm

def check_token_length():
    model_name = 'microsoft/graphcodebert-base'
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)

    train_data_json = load_from_json_file("TestCases/model_train/model_1/train_data/train_data.json")
    data_items = []
    for item in train_data_json:
        data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    for data_item in data_items:
        text = data_item.get_train_text(tokenizer.sep_token)

        encoding = tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            # max_length=512,
            # padding='max_length',
            # truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )

        if len(encoding['input_ids'][0]) > 512:
            print()
            print(data_item.function_name, len(encoding['input_ids'][0]))

from transformers import BigBirdTokenizer

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel
from main.models.function_confirm_model.model_training import init_train
from tqdm import tqdm

def check_token_length_bigbird():
    model_name = 'google/bigbird-roberta-base'  # 使用BigBird的预训练模型名称
    tokenizer = BigBirdTokenizer.from_pretrained(model_name)
    for special_token in DataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)

    train_data_json = load_from_json_file("TestCases/model_train/model_1/train_data/train_data.json")
    data_items = []
    for item in train_data_json:
        data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    for data_item in data_items:
        text = data_item.get_train_text(tokenizer.sep_token)

        encoding = tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            # BigBird支持的最大长度更长，但是这里不设置max_length就不会应用截断
            return_attention_mask=True,
            return_tensors='pt',
            padding='max_length',
        )

        # 由于BigBird支持的长度比Roberta更长，这里的阈值可以相应调整
        # BigBird原论文提到支持的长度可达到4096个tokens
        if len(encoding['input_ids'][0]) < 700:
            print()
            print(data_item.function_name, len(encoding['input_ids'][0]))

# check_token_length()
#
check_token_length_bigbird()