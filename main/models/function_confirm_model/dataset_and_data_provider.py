import multiprocessing
from random import shuffle
from typing import List

import torch
from loguru import logger
from torch.utils.data import Dataset, DataLoader
from tqdm import tqdm

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForFunctionConfirmModel


class FunctionConfirmDataset(Dataset):
    def __init__(self, item_ids, texts, labels, tokenizer, max_len=512):
        self.item_ids = item_ids  # 用于记录原始数据的id, 方便调试
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx):
        item_id = self.item_ids[idx]
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
            'item_ids': item_id,
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'labels': torch.tensor(label, dtype=torch.long)
        }


def create_dataset_from_model_input(data_items: List[DataItemForFunctionConfirmModel], tokenizer, max_len=512):
    texts = []
    labels = []
    item_ids = []
    for data_item in data_items:
        item_ids.append(data_item.id)
        data_item.normalize()
        texts.append(data_item.get_train_text(tokenizer.sep_token))
        labels.append(data_item.label)

    dataset = FunctionConfirmDataset(item_ids, texts, labels, tokenizer, max_len)
    return dataset


def init_data_item_obj_from_dict(item):
    data_item = DataItemForFunctionConfirmModel.init_from_dict(item)
    data_item.normalize()
    return data_item


def create_dataset(file_path, tokenizer, max_len=512, is_train=False):
    logger.info(f"加载数据集: {file_path}")
    train_data_json = load_from_json_file(file_path)
    logger.info(f"加载完毕")

    pool = multiprocessing.Pool(multiprocessing.cpu_count() - 4)
    data_items = list(
        tqdm(pool.imap_unordered(init_data_item_obj_from_dict, train_data_json), total=len(train_data_json),
             desc="多进程初始化训练对象"))
    pool.close()
    pool.join()

    texts = []
    labels = []
    item_ids = []
    for data_item in tqdm(data_items, desc="构建Dataset参数"):
        item_ids.append(data_item.id)
        labels.append(data_item.label)
        texts.append(data_item.get_train_text(tokenizer.sep_token))

    print("原始数据数量: ", len(texts))
    print("原始数据标签分布: ", {label: labels.count(label) for label in set(labels)})
    dataset = FunctionConfirmDataset(item_ids, texts, labels, tokenizer, max_len)
    logger.info(f"数据集构建完毕, 数据集大小: {len(dataset)}")
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
