from torch.utils.data import DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetPositioningModel, DataItemForCodeSnippetConfirmModel

from torch.utils.data import Dataset
import torch


class CodeSnippetConfirmDataset(Dataset):
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


def create_dataset(file_path, tokenizer, max_len=512):
    train_data_json = load_from_json_file(file_path)
    data_items = []
    for item in train_data_json:
        data_item = DataItemForCodeSnippetConfirmModel.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    texts = []
    labels = []
    for data_item in data_items:
        texts.append(data_item.get_text(tokenizer.sep_token))
        labels.append(data_item.get_label())

    print("原始数据数量: ", len(texts))
    print("原始数据标签分布: ", {label: labels.count(label) for label in set(labels)})
    dataset = CodeSnippetConfirmDataset(texts, labels, tokenizer, max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
