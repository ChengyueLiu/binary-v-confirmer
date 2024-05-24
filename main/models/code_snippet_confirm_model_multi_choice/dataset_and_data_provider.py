import multiprocessing
import random
from collections import Counter

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
    def __init__(self, questions, choice_0_list, choice_1_list, choice_index_list, tokenizer, question_types=None,
                 max_len=512):
        self.questions = questions
        if question_types is None:
            self.question_types = [0] * len(questions)
        else:
            self.question_types = question_types
        self.choice_0_list = choice_0_list
        self.choice_1_list = choice_1_list
        self.choice_index_list = choice_index_list
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.questions)

    def __getitem__(self, idx):
        question = self.questions[idx]
        question_type = self.question_types[idx]
        choice_0 = self.choice_0_list[idx]
        choice_1 = self.choice_1_list[idx]
        choice_index = self.choice_index_list[idx]

        # 使用tokenizer的__call__方法同时处理问题和选项
        # 注意：我们需要为每个选项重复问题文本
        prompts = [question, question]
        choices = [choice_0, choice_1]
        encoding = self.tokenizer(prompts, choices,
                                  max_length=self.max_len,
                                  truncation=True,
                                  padding='max_length',
                                  return_tensors='pt')

        # 注意：不要使用squeeze(0)，因为我们需要保持批量维度
        input_ids = encoding['input_ids']
        attention_mask = encoding['attention_mask']
        labels = torch.tensor(choice_index, dtype=torch.long)  # 不需要unsqueeze(0)

        return {
            'question_types': question_type,
            'input_ids': input_ids,  # Shape: [1, num_choices, sequence_length]
            'attention_mask': attention_mask,  # Shape: [1, num_choices, sequence_length]
            'labels': labels
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

    # print("原始数据数量: ",
    dataset = CodeSnippetConfirmDataset(questions, choice_0_list, choice_1_list, choice_index_list, tokenizer,
                                        max_len=max_len)
    return dataset


def create_dataset(file_path, tokenizer, max_len=512):
    logger.info(f"读取文件：{file_path}")
    train_data_json = load_from_json_file(file_path)
    pool = multiprocessing.Pool(multiprocessing.cpu_count() - 4)
    data_items = list(
        tqdm(pool.imap_unordered(init_data_item_obj_from_dict, train_data_json), total=len(train_data_json),
             desc="多进程初始化训练对象"))
    pool.close()
    pool.join()

    questions = []
    question_types = []
    choice_0_list = []
    choice_1_list = []
    choice_index_list = []
    for data_item in data_items:
        src_codes_0_text = data_item.get_src_codes_0_text()
        src_codes_1_text = data_item.get_src_codes_1_text()
        if not src_codes_0_text or not src_codes_1_text:
            continue
        if data_item.wrong_type == 1:
            continue
        questions.append(data_item.get_question_text())
        question_types.append(data_item.wrong_type)
        choice_0_list.append(src_codes_0_text)
        choice_1_list.append(src_codes_1_text)
        choice_index_list.append(data_item.choice_index)
    counter = Counter(question_types)
    print("原始数据数量: ", len(questions), " 类别分布: ", counter)
    dataset = CodeSnippetConfirmDataset(questions, choice_0_list, choice_1_list, choice_index_list, tokenizer,
                                        question_types=question_types, max_len=max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=8, pin_memory=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=8, pin_memory=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=8, pin_memory=True)
    return train_loader, val_loader, test_loader
