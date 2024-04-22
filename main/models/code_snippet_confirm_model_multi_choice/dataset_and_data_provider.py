import random

import transformers
from torch.utils.data import DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetConfirmModelMC

from torch.utils.data import Dataset
import torch

# 移除这个烦人的警告：Be aware, overflowing tokens are not returned for the setting you have chosen, i.e. sequence pairs with the 'longest_first' truncation strategy. So the returned list will always be empty even if some tokens have been removed.
transformers.logging.set_verbosity_error()


class CodeSnippetConfirmDataset(Dataset):
    def __init__(self, questions, choice_1_list, choice_2_list, tokenizer, max_len=512, shuffle_choices=True):
        """
        set choice 1 as the right answer when training
        """
        self.questions = questions
        self.choice_1_list = choice_1_list
        self.choice_2_list = choice_2_list
        self.tokenizer = tokenizer
        self.max_len = max_len
        self.shuffle_choices = shuffle_choices

    def __len__(self):
        return len(self.questions)

    def __getitem__(self, idx):
        question = self.questions[idx]
        choice_1 = self.choice_1_list[idx]
        choice_2 = self.choice_2_list[idx]

        # 将正确答案和错误答案合并到一个列表中，并可能打乱它们的顺序
        choices = [choice_1, choice_2]
        if self.shuffle_choices:
            random.shuffle(choices)
        # 确定正确答案在打乱后的列表中的索引
        label = choices.index(choice_1)

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
            'labels': torch.tensor(label, dtype=torch.long)
        }


def create_dataset(file_path, tokenizer, max_len=512):
    train_data_json = load_from_json_file(file_path)
    data_items = []
    for item in train_data_json:
        data_item = DataItemForCodeSnippetConfirmModelMC.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    questions = []
    right_answers = []
    wrong_answers = []
    for data_item in data_items:
        questions.append(data_item.get_question_text())
        right_answers.append(data_item.get_right_answer_text())
        wrong_answers.append(data_item.get_wrong_answer_text())

    print("原始数据数量: ", len(questions))
    dataset = CodeSnippetConfirmDataset(questions, right_answers, wrong_answers, tokenizer, max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
