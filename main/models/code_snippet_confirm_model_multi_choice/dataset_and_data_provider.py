import random

from torch.utils.data import DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetConfirmModelMC

from torch.utils.data import Dataset
import torch


class CodeSnippetConfirmDataset(Dataset):
    def __init__(self, questions, choice_1_list, choice_2_list, tokenizer, max_len=512,shuffle_choices=True):
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

        # 将正确答案和错误答案合并到一个列表中
        choices = [choice_1,choice_2]
        # 打乱答案的顺序
        if self.shuffle_choices:
            random.shuffle(choices)
        # 确定正确答案在打乱后的列表中的索引
        label = choices.index(choice_1)

        input_ids = []
        attention_masks = []
        for choice in choices:
            encoding = self.tokenizer.encode_plus(
                text=question,
                text_pair=choice,
                add_special_tokens=True,
                max_length=self.max_len,
                padding='max_length',
                truncation=True,
                return_attention_mask=True,
                return_tensors='pt',
            )
            input_ids.append(encoding['input_ids'].squeeze(0))
            attention_masks.append(encoding['attention_mask'].squeeze(0))

        input_ids = torch.stack(input_ids)
        attention_masks = torch.stack(attention_masks)

        return {
            'input_ids': input_ids,
            'attention_mask': attention_masks,
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
        wrong_answers.extend(data_item.get_wrong_answer_texts())

    print("原始数据数量: ", len(questions))
    dataset = CodeSnippetConfirmDataset(questions, right_answers,wrong_answers, tokenizer, max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
