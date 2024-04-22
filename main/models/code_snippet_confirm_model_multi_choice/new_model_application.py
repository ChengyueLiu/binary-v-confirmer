from typing import List

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForMultipleChoice

from main.interface import DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.dataset_and_data_provider import CodeSnippetConfirmDataset


class SnippetChoicer:
    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self) -> (torch.device, RobertaTokenizer, RobertaForMultipleChoice):

        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        for special_token in DataItemForCodeSnippetConfirmModelMC.get_special_tokens():
            tokenizer.add_tokens(special_token)

        # model
        model = RobertaForMultipleChoice.from_pretrained(self.model_name, num_labels=self.num_labels)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def predict(self, data: DataItemForCodeSnippetConfirmModelMC) -> List[int]:
        dataloader = self.create_dataloader(data)
        return self._predict(dataloader)