from loguru import logger
from torch.utils.data import DataLoader

from bintools.general.file_tool import load_from_json_file
from main.interface import DataItemForCodeSnippetPositioningModel

from torch.utils.data import Dataset
import torch


def get_answer_tokens_index(answer_start_char, answer_end_char, offset_mapping):
    """
    根据答案的字符级别的开始和结束位置，找到对应的token级别的开始和结束位置

    :param answer_start_char: answer在context中的开始位置
    :param answer_end_char: answer在context中的结束位置
    :param offset_mapping: tokenizer 的返回值，表示每个token在原始文本中的开始和结束位置
    :return:
    """

    # 初始化答案的token位置
    answer_start_token_index, answer_end_token_index = None, None
    # 遍历每个token的偏移量
    for i, (start, end) in enumerate(offset_mapping):
        # print(i, tokens[i], start, end, answer_start_char, answer_end_char)
        # 确定答案开始token的索引
        if (answer_start_token_index is None) and (start <= answer_start_char < end):
            answer_start_token_index = i
        # 确定答案结束token的索引
        if (answer_end_token_index is None) and (start < answer_end_char <= end):
            answer_end_token_index = i

    return answer_start_token_index, answer_end_token_index


class CodeSnippetPositioningDataset(Dataset):
    def __init__(self, questions, contexts, answer_start_indexes, answer_end_indexes, tokenizer, max_len=512):
        """
        初始化问答数据集
        :param contexts: 上下文列表，每个上下文是一段文本（答案所在的文本）
        :param questions: 问题列表，每个问题对应上面的上下文
        :param tokenizer: 使用的tokenizer
        :param max_len: 输入序列的最大长度
        """
        self.contexts = contexts
        self.questions = questions
        self.answer_start_indexes = answer_start_indexes
        self.answer_end_indexes = answer_end_indexes
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.contexts)

    def __getitem__(self, idx):
        # Tokenize context and question
        encoding = self.tokenizer.encode_plus(
            self.questions[idx],
            self.contexts[idx],
            add_special_tokens=True,
            max_length=self.max_len,
            padding='max_length',
            truncation=True,
            return_attention_mask=True,
            return_offsets_mapping=True,  # 需要offsets来计算答案位置
            return_tensors='pt',
        )

        # 根据答案的字符级别的开始和结束位置，找到对应的token级别的开始和结束位置
        answer_tokens_start_index, answer_tokens_end_index = get_answer_tokens_index(
            self.answer_start_indexes[idx],
            self.answer_end_indexes[idx],
            encoding['offset_mapping'].squeeze())

        if not answer_tokens_start_index:
            answer_tokens_start_index = 0
            answer_tokens_end_index = 0

        elif not answer_tokens_end_index:
            answer_tokens_end_index = self.max_len - 1

        if answer_tokens_end_index < answer_tokens_start_index:
            logger.warning(f"answer_start_index: {self.answer_start_indexes[idx]}, answer_end_index: {self.answer_end_indexes[idx]}")
            logger.warning(f"answer_tokens_end_index < answer_tokens_start_index: {answer_tokens_end_index} < {answer_tokens_start_index}")
        answer_tokens_start_index_tensor = torch.tensor([answer_tokens_start_index])
        answer_tokens_end_index_tensor = torch.tensor([answer_tokens_end_index])

        return {
            'input_ids': encoding['input_ids'].flatten(),
            'attention_mask': encoding['attention_mask'].flatten(),
            'start_positions': answer_tokens_start_index_tensor,
            'end_positions': answer_tokens_end_index_tensor,
        }


def create_dataset(file_path, tokenizer, max_len=512):
    train_data_json = load_from_json_file(file_path)
    data_items = []
    for item in train_data_json:
        data_item = DataItemForCodeSnippetPositioningModel.init_from_dict(item)
        data_item.normalize()
        data_items.append(data_item)

    questions = []
    contexts = []
    answer_start_indexes = []
    answer_end_indexes = []
    for data_item in data_items:
        questions.append(data_item.get_question_text())
        contexts.append(data_item.get_context_text())
        answer_start_index, answer_end_index = data_item.get_answer_position()
        answer_start_indexes.append(answer_start_index)
        answer_end_indexes.append(answer_end_index)

    print("原始数据数量: ", len(questions))
    dataset = CodeSnippetPositioningDataset(questions,
                                            contexts,
                                            answer_start_indexes,
                                            answer_end_indexes,
                                            tokenizer,
                                            max_len=max_len)
    return dataset


def create_dataloaders(train_dataset, val_dataset, test_dataset, batch_size=16):
    train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return train_loader, val_loader, test_loader
