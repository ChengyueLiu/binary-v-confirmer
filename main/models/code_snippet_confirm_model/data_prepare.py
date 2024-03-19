import random

from bintools.general.file_tool import load_from_json_file, save_to_json_file
from main.interface import DataItemForCodeSnippetPositioningModel, DataItemForCodeSnippetConfirmModel


def generate_data_items(file_path: str, save_path: str):
    # step 1: 读取第二步的数据
    model_2_train_data_json = load_from_json_file(file_path)
    model_2_train_data_items = [DataItemForCodeSnippetPositioningModel.init_from_dict(item) for item in
                                model_2_train_data_json]

    # step 2: 生成例子
    train_data_items = [DataItemForCodeSnippetConfirmModel(
        src_codes=item.src_codes,
        asm_codes=item.asm_codes[item.answer_start_index:item.answer_end_index + 1],
        label=1,
        normalize=False
    ) for item in model_2_train_data_items]

    # step 3: 生成负例
    negative_examples = []
    for positive_item in model_2_train_data_items:
        # 为每个正例生成3个负例
        for _ in range(3):
            # 随机选择一个不同的条目作为负例的源
            while True:
                random_item = random.choice(model_2_train_data_items)
                # 确保选中的负例和当前的正例不相同
                if random_item.asm_codes != positive_item.asm_codes:
                    break
            # 创建负例数据项
            # TODO 后续这里要增加那种commit 前后的代码变化的数据，就是那种微小的变化，目前都是大的变化
            negative_example = DataItemForCodeSnippetConfirmModel(
                src_codes=positive_item.src_codes,  # 使用正例的 src_codes
                asm_codes=random_item.asm_codes,  # 使用随机选择的不相关的 asm_codes
                label=0,  # 标签设置为0
                normalize=False
            )
            negative_examples.append(negative_example)

    # step 3: 保存
    all_data_items = train_data_items + negative_examples
    train_data_items_json = [item.custom_serialize() for item in all_data_items]
    save_to_json_file(train_data_items_json, save_path)
