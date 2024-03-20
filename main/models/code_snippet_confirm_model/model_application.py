import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import RobertaTokenizer, RobertaForSequenceClassification

from main.interface import DataItemForCodeSnippetConfirmModel
from main.models.code_snippet_confirm_model.dataset_and_data_provider import CodeSnippetConfirmDataset


class SnippetConfirmer:
    def __init__(self, model_save_path: str = 'model_weights.pth', batch_size: int = 16):
        self.model_name = 'microsoft/graphcodebert-base'
        self.num_labels = 2

        self.model_save_path: str = model_save_path
        self.batch_size: int = batch_size

        # init
        self.device, self.tokenizer, self.model = self._init_predict()

    def _init_predict(self) -> (torch.device, RobertaTokenizer, RobertaForSequenceClassification):

        # device
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

        # tokenizer
        tokenizer = RobertaTokenizer.from_pretrained(self.model_name)
        for special_token in DataItemForCodeSnippetConfirmModel.get_special_tokens():
            tokenizer.add_tokens(special_token)

        # model
        model = RobertaForSequenceClassification.from_pretrained(self.model_name, num_labels=self.num_labels)
        model.resize_token_embeddings(len(tokenizer))
        model = torch.nn.DataParallel(model).to(device)
        model.load_state_dict(torch.load(self.model_save_path))
        model.eval()

        return device, tokenizer, model

    def _preprocess_data(self, src_codes_text: str, asm_codes_text_list: str):
        texts = [f"{src_codes_text} {self.tokenizer.sep_token} {asm_codes_text}"
                 for asm_codes_text in asm_codes_text_list]
        labels = [0] * len(asm_codes_text_list)
        dataset = CodeSnippetConfirmDataset(texts, labels, self.tokenizer)
        train_loader = DataLoader(dataset, batch_size=self.batch_size, shuffle=True)
        return train_loader

    def _predict(self, dataloader):
        """

        :param dataloader:
        :return: [(pred, prob), ...]
        """
        # predict
        predictions = []
        for batch in tqdm(dataloader, desc="confirming functions ..."):
            input_ids = batch['input_ids'].to(self.device)
            attention_mask = batch['attention_mask'].to(self.device)
            with torch.no_grad():
                # model: RobertaForSequenceClassification
                outputs = self.model(input_ids, attention_mask=attention_mask)
            logits = outputs.logits
            # 使用softmax计算概率
            probabilities = F.softmax(logits, dim=-1)

            # 找到每个样本的最大概率及其索引
            max_probs, preds = torch.max(probabilities, dim=-1)
            for pred, prob in zip(preds, max_probs):
                predictions.append((pred, prob))
        return predictions

    def confirm_vuls(self, src_codes_text, asm_codes_text_list):
        """
        输入一个源代码函数代码，和一个二进制文件，返回二进制文件中与源代码函数相似的汇编函数

        """
        # 预处理数据
        dataloader = self._preprocess_data(src_codes_text, asm_codes_text_list)

        # 预测
        predictions = self._predict(dataloader)

        return predictions
