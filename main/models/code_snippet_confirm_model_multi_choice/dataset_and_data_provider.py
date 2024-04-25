import multiprocessing
import random

import transformers
from loguru import logger
from torch.utils.data import DataLoader
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetConfirmModelMC

from torch.utils.data import Dataset
import torch

# 移除这个烦人的警告：Be aware, overflowing tokens are not returned for the setting you have chosen, i.e. sequence pairs with the 'longest_first' truncation strategy. So the returned list will always be empty even if some tokens have been removed.
transformers.logging.set_verbosity_error()


class CodeSnippetConfirmDataset(Dataset):
    def __init__(self, questions, choice_0_list, choice_1_list, choice_index_list, tokenizer, max_len=512):
        """
        set choice 1 as the right answer when training
        """
        self.questions = questions
        self.choice_0_list = choice_0_list
        self.choice_1_list = choice_1_list
        self.choice_index_list = choice_index_list
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.questions)

    def __getitem__(self, idx):
        question = self.questions[idx]
        choice_0 = self.choice_0_list[idx]
        choice_1 = self.choice_1_list[idx]
        choice_index = self.choice_index_list[idx]
        choices = [choice_0, choice_1]

        # 使用tokenizer的__call__方法同时处理问题和选项
        # 注意：我们需要为每个选项重复问题文本
        prompts = [question] * len(choices)  # 重复问题以匹配每个选项
        encoding = self.tokenizer(prompts, choices,
                                  max_length=self.max_len,
                                  truncation=True,
                                  padding='max_length',
                                  return_tensors='pt')

        input_ids = encoding['input_ids']
        attention_mask = encoding['attention_mask']

        # 由于在这种情况下不需要手动堆叠，返回值保持不变
        return {
            'input_ids': input_ids,
            'attention_mask': attention_mask,
            'labels': torch.tensor(choice_index, dtype=torch.long)
        }


def init_data_item_obj_from_dict(item):
    data_item = DataItemForCodeSnippetConfirmModelMC.init_from_dict(item)
    data_item.normalize()
    return data_item

def create_dataset_from_model_input(data_items, tokenizer, max_len=512):
    questions = []
    choice_0_list = []
    choice_1_list = []
    choice_index_list = []
    for data_item in data_items:
        questions.append(data_item.get_question_text())
        choice_0_list.append(data_item.get_src_codes_0_text())
        choice_1_list.append(data_item.get_src_codes_1_text())
        choice_index_list.append(data_item.choice_index)

    # print("原始数据数量: ", len(questions))
    dataset = CodeSnippetConfirmDataset(questions, choice_0_list, choice_1_list, choice_index_list, tokenizer, max_len)
    return dataset
def create_dataset(file_path, tokenizer, max_len=512):
    logger.info(f"读取文件：{file_path}")
    train_data_json = load_from_json_file(file_path)
    random.shuffle(train_data_json)
    train_data_json = train_data_json  # TODO 用100万个做实验
    pool = multiprocessing.Pool(multiprocessing.cpu_count() - 4)
    data_items = list(
        tqdm(pool.imap_unordered(init_data_item_obj_from_dict, train_data_json), total=len(train_data_json),
             desc="多进程初始化训练对象"))
    pool.close()
    pool.join()

    questions = []
    choice_0_list = []
    choice_1_list = []
    choice_index_list = []
    for data_item in data_items:
        questions.append(data_item.get_question_text())
        choice_0_list.append(data_item.get_src_codes_0_text())
        choice_1_list.append(data_item.get_src_codes_1_text())
        choice_index_list.append(data_item.choice_index)

    print("原始数据数量: ", len(questions))
    dataset = CodeSnippetConfirmDataset(questions, choice_0_list, choice_1_list, choice_index_list, tokenizer, max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
