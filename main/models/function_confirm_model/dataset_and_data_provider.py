import random
from typing import List

import torch
from loguru import logger
from torch.utils.data import Dataset, random_split, DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import TrainDataItemForFunctionConfirmModel


class FunctionConfirmDataset(Dataset):
    def __init__(self, texts, labels, tokenizer, max_len=512):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        text = self.texts[idx]
        label = self.labels[idx]

        encoding = self.tokenizer.encode_plus(
            text,
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_tensors='pt',
        )

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


def generate_negative_examples(texts, labels, ratio=1.0):
    # ratio表示生成反例的比例
    negative_texts = []
    negative_labels = []

    num_negatives = int(len(texts) * ratio)
    indices = list(range(len(texts)))
    random.shuffle(indices)  # 打乱索引

    for i in range(num_negatives):
        idx = indices[i]
        negative_texts.append(texts[idx])
        # 假设原始标签为1，反例标签为0
        negative_labels.append(0)  # 或者是 1-labels[idx] 如果标签是二元的

    # 将反例添加到原数据中
    augmented_texts = texts + negative_texts
    augmented_labels = labels + negative_labels

    # 再次打乱数据以混合正例和反例
    combined = list(zip(augmented_texts, augmented_labels))
    random.shuffle(combined)
    augmented_texts, augmented_labels = zip(*combined)

    return augmented_texts, augmented_labels


def create_datasets(train_data_json_file_path, tokenizer, max_len=512, n_to_p_ratio=3.0):
    train_data_json = load_from_json_file(train_data_json_file_path)
    train_data_items = [TrainDataItemForFunctionConfirmModel.init_from_dict(item) for item in train_data_json]

    texts = []
    labels = []

    for train_data_item in train_data_items:
        texts.append(train_data_item.get_train_text())
        labels.append(train_data_item.label)

    # 增加反例
    texts, labels = generate_negative_examples(texts, labels, ratio=n_to_p_ratio)
    logger.info(f"Total number of training examples: {len(texts)}, ratio of negative to positive: {n_to_p_ratio}")

    dataset = FunctionConfirmDataset(texts, labels, tokenizer, max_len)

    # random split
    train_size = int(0.8 * len(dataset))
    val_size = int(0.1 * len(dataset))
    test_size = len(dataset) - train_size - val_size
    train_dataset, val_dataset, test_dataset = random_split(dataset, [train_size, val_size, test_size])

    return train_dataset, val_dataset, test_dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
