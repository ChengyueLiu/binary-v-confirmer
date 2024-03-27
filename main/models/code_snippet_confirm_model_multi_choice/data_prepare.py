import copy
import random

from bintools.general.file_tool import load_from_json_file, save_to_json_file
from main.interface import DataItemForCodeSnippetPositioningModel, DataItemForCodeSnippetConfirmModelMC

def modify_list(str_list):
    # 创建列表的副本，以便进行修改
    modified_list = copy.deepcopy(str_list)
    # 计算随机位置的数量，1-3
    num_positions = random.randint(1, 3)

    for _ in range(num_positions):
        if modified_list:  # 确保列表不为空
            # 选择一个随机位置
            pos = random.randint(0, len(modified_list) - 1)
            # 随机选择删除或插入
            action = random.choice(['delete', 'insert'])
            if action == 'delete':
                # 执行删除操作
                del modified_list[pos]
            else:
                # 执行插入操作
                # 随机选择一个字符串来插入
                string_to_insert = random.choice(str_list)
                modified_list.insert(pos + 1, string_to_insert)

    return modified_list

def generate_data_items(file_path: str, save_path: str):
    # step 1: 读取第二步的数据
    model_2_train_data_json = load_from_json_file(file_path)
    model_2_train_data_items = [DataItemForCodeSnippetPositioningModel.init_from_dict(item) for item in
                                model_2_train_data_json]

    # step 3: 生成训练例子
    train_data_items = []
    for positive_item in model_2_train_data_items:
        # 生成完全不相干的例子
        # 随机选择一个不同的条目作为负例的源
        while True:
            random_item = random.choice(model_2_train_data_items)
            # 确保选中的负例和当前的正例不相同
            if random_item.asm_codes != positive_item.asm_codes:
                break
        train_data_item = DataItemForCodeSnippetConfirmModelMC(
            asm_codes=positive_item.answer_asm_codes,
            right_src_codes=positive_item.src_codes,
            wrong_src_codes=random_item.src_codes,
        )
        train_data_items.append(train_data_item)

        # 生成3个很相似的例子
        for _ in range(3):
            modified_src_codes = modify_list(positive_item.src_codes)
            if modified_src_codes == positive_item.src_codes:
                continue
            # 随机减少1-3行代码
            train_data_item = DataItemForCodeSnippetConfirmModelMC(
                asm_codes=positive_item.answer_asm_codes,
                right_src_codes=positive_item.src_codes,
                wrong_src_codes=modified_src_codes,
            )
            train_data_items.append(train_data_item)
    train_data_items_json = [item.custom_serialize() for item in train_data_items]
    save_to_json_file(train_data_items_json, save_path)
