from typing import List

import torch
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


def create_datasets(train_data_json_file_path, tokenizer, max_len=512):
    train_data_json = load_from_json_file(train_data_json_file_path)
    train_data_items = [TrainDataItemForFunctionConfirmModel(item) for item in train_data_json]

    texts = []
    labels = []

    for train_data_item in train_data_items:
        texts.append(train_data_item.get_train_text())
        labels.append(train_data_item.label)

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
