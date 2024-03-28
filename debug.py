# tokenizer
from tqdm import tqdm
from transformers import RobertaTokenizer

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel
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


for data_item in tqdm(data_items):
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
    # 输出token长度
    token_length = len(encoding['input_ids'][0])
    if token_length>512:
        print(token_length)