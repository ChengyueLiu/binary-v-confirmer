from typing import List

import torch
from torch.utils.data import Dataset, DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel

from torch.utils.data import Dataset
import torch


class CodeSnippetPositioningDataset(Dataset):
    def __init__(self, contexts, questions, answers, tokenizer, max_len=512):
        """
        初始化问答数据集
        :param contexts: 上下文列表，每个上下文是一段文本（答案所在的文本）
        :param questions: 问题列表，每个问题对应上面的上下文
        :param tokenizer: 使用的tokenizer
        :param max_len: 输入序列的最大长度
        """
        self.contexts = contexts
        self.questions = questions
        self.answers = answers
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.contexts)

    def find_answer_positions(self, context, question, answer):
        """
        根据上下文、问题和答案，找到答案的开始和结束token位置。

        参数:
        - context: 上下文文本
        - question: 问题文本
        - answer: 答案文本
        - tokenizer: 使用的tokenizer

        返回:
        - start_position: 答案的开始token位置
        - end_position: 答案的结束token位置
        """
        # 对上下文和问题进行tokenize处理
        inputs = self.tokenizer.encode_plus(question, context,
                                            add_special_tokens=True,
                                            return_tensors='pt',
                                            return_offsets_mapping=True)
        offsets = inputs['offset_mapping'].squeeze().tolist()  # 获取每个token的字符级别位置

        # 查找答案的开始和结束字符位置
        answer_start_index = context.index(answer)
        answer_end_index = answer_start_index + len(answer) - 1

        # 将答案的字符位置转换为token位置
        start_position = end_position = None
        for idx, (start, end) in enumerate(offsets):
            if (start_position is None) and (start <= answer_start_index < end):
                start_position = idx
            if (end_position is None) and (start < answer_end_index <= end):
                end_position = idx
                break

        return start_position, end_position

    def __getitem__(self, idx):
        context = self.contexts[idx]
        question = self.questions[idx]
        start_position, end_position = self.find_answer_positions(context, question, self.answers[idx])

        # Tokenize context and question
        encoding = self.tokenizer.encode_plus(
            question,
            context,
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_offsets_mapping=True,  # 需要offsets来计算答案位置
            return_tensors='pt',
        )

        # Your tokenizer needs to support return_offsets_mapping
        offsets = encoding['offset_mapping'].squeeze()  # Batch size 为 1

        # 我们需要将start_position和end_position从字符位置转换为token位置
        cls_index = torch.where(encoding['input_ids'] == self.tokenizer.cls_token_id)[1]
        sequence_ids = encoding.sequence_ids()

        # 如果答案不能在当前的编码中找到，我们将答案标记为CLS标记的位置
        if start_position is not None and end_position is not None:
            start_position, end_position = self.adjust_positions(start_position, end_position, offsets, sequence_ids,
                                                                 cls_index)

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'start_positions': torch.tensor(start_position, dtype=torch.long),
            'end_positions': torch.tensor(end_position, dtype=torch.long),
        }

    def adjust_positions(self, start_char, end_char, offsets, sequence_ids, cls_index):
        """
        调整字符位置到token位置
        """
        start_token = None
        end_token = None

        for i, (offset, seq_id) in enumerate(zip(offsets, sequence_ids)):
            if seq_id is None or seq_id == 0:  # 属于question的部分或者特殊token
                continue
            if start_token is None and offset[0] <= start_char < offset[1]:
                start_token = i
            if offset[0] <= end_char < offset[1]:
                end_token = i

        # 如果找不到合适的token位置，就把答案标记为CLS的位置
        start_token = start_token if start_token is not None else cls_index
        end_token = end_token if end_token is not None else cls_index

        return start_token, end_token


def create_dataset(file_path, tokenizer, max_len=512):
    train_data_json = load_from_json_file(file_path)
    train_data_items = [DataItemForFunctionConfirmModel.init_from_dict(item) for item in train_data_json]

    texts = []
    labels = []
    for train_data_item in train_data_items:
        texts.append(train_data_item.get_train_text(tokenizer.sep_token))
        labels.append(train_data_item.label)

    print("原始数据数量: ", len(texts))
    print("原始数据标签分布: ", {label: labels.count(label) for label in set(labels)})
    dataset = CodeSnippetPositioningDataset(texts, labels, tokenizer, max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader