import torch
from loguru import logger
from torch.utils.data import DataLoader
from tqdm import tqdm
from transformers import AdamW, get_linear_schedule_with_warmup, RobertaTokenizer, RobertaForQuestionAnswering, \
    AutoTokenizer

from main.interface import DataItemForCodeSnippetPositioningModel
from main.models.code_snippet_positioning_model.dataset_and_data_provider import create_dataset, create_dataloaders


def init_train(train_data_json_file_path,
               val_data_json_file_path,
               test_data_json_file_path,
               model_name='microsoft/graphcodebert-base',
               token_max_length=512,
               batch_size=512,
               learn_rate=5e-5,
               epochs=3,
               test_only=False):
    """

    :param test_data_json_file_path:
    :param val_data_json_file_path:
    :param train_data_json_file_path:
    :param num_labels: 标签类型数量
    :param model_name: 模型名称
    :param token_max_length: token最大长度
    :param batch_size: 批量大小
    :param learn_rate: 学习率
    :param epochs: 训练轮数
    :return:
    """
    # device
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')

    # tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    for special_token in DataItemForCodeSnippetPositioningModel.get_special_tokens():
        tokenizer.add_tokens(special_token)

    # model
    model = RobertaForQuestionAnswering.from_pretrained(model_name)
    model.resize_token_embeddings(len(tokenizer))
    model = torch.nn.DataParallel(model).to(device)

    # datasets
    if test_only:
        train_dataset = None
        val_dataset = None
    else:
        train_dataset = create_dataset(train_data_json_file_path, tokenizer, token_max_length)
        val_dataset = create_dataset(val_data_json_file_path, tokenizer, token_max_length)
    test_dataset = create_dataset(test_data_json_file_path, tokenizer, token_max_length)

    # dataloader
    logger.info(f"batch size: {batch_size}")
    if test_only:
        train_loader = None
        val_loader = None
    else:
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True, num_workers=8, pin_memory=True)
        val_loader = DataLoader(val_dataset, batch_size=batch_size, shuffle=False, num_workers=8, pin_memory=True)
    test_loader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False, num_workers=8, pin_memory=True)

    # optimizer
    optimizer = AdamW(model.parameters(), lr=learn_rate)

    if test_only:
        total_steps = len(test_loader) * epochs
    else:
        total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)
    return device, tokenizer, model, train_loader, val_loader, test_loader, optimizer, scheduler


# 辅助函数：计算重叠和长度
def calculate_overlap(true_start, true_end, pred_start, pred_end):
    if pred_end <= pred_start:
        pred_end = pred_start + 350
    # 计算真实答案和预测答案的交集
    overlap = max(0, min(true_end, pred_end) - max(true_start, pred_start) + 1)
    true_length = true_end - true_start + 1
    pred_length = pred_end - pred_start + 1
    return overlap, true_length, pred_length


# 定义训练和评估函数
def train_or_evaluate(model, iterator, optimizer, scheduler, device, is_train=True):
    if is_train:
        model.train()
    else:
        model.eval()

    epoch_loss = 0
    total_overlap = 0
    total_true_length = 0
    total_pred_length = 0

    for batch in tqdm(iterator, desc="Processing batches"):
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        start_positions = batch['start_positions'].to(device)
        end_positions = batch['end_positions'].to(device)

        if is_train:
            optimizer.zero_grad()

        with torch.set_grad_enabled(is_train):
            outputs = model(input_ids=input_ids,
                            attention_mask=attention_mask,
                            start_positions=start_positions,
                            end_positions=end_positions)
            loss = outputs.loss
            # 下面两行是为了适配多GPU训练
            if loss.dim() > 0:  # 如果损失不是标量
                loss = loss.mean()  # 计算所有损失的平均值确保是标量
            predict_answer_tokens_start_indices = outputs.start_logits.argmax(dim=1)
            predict_answer_tokens_end_indices = outputs.end_logits.argmax(dim=1)

            if is_train:
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                scheduler.step()

        epoch_loss += loss.item()

        # 计算重叠和长度
        for true_start, true_end, pred_start, pred_end in zip(start_positions,
                                                              end_positions,
                                                              predict_answer_tokens_start_indices,
                                                              predict_answer_tokens_end_indices):
            overlap, true_length, pred_length = calculate_overlap(true_start.item(),
                                                                  true_end.item(),
                                                                  pred_start.item(),
                                                                  pred_end.item())
            total_overlap += overlap
            total_true_length += true_length
            total_pred_length += pred_length
            if overlap > true_length:
                logger.warning(f'overlap: {overlap} > true_length: {true_length}')

    precision = total_overlap / total_pred_length if total_pred_length > 0 else 0
    recall = total_overlap / total_true_length if total_true_length > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return epoch_loss / len(iterator), precision, recall, f1


# 准备训练
def run_train(train_data_json_file_path,
              val_data_json_file_path,
              test_data_json_file_path,
              back_model_save_path="model_weights_back.pth",
              model_save_path="model_weights.pth",
              test_only=False,
              **kwargs):
    batch_size = kwargs.get('batch_size', 32)
    epochs = kwargs.get('epochs', 3)
    # 初始化训练
    logger.info('Init train...')
    device, tokenizer, model, train_loader, val_loader, test_loader, optimizer, scheduler = init_train(
        train_data_json_file_path,
        val_data_json_file_path,
        test_data_json_file_path,
        test_only=test_only,
        **kwargs)  # 确保其他参数也能被传递
    logger.info('Initialized, start training, epochs: {}, batch_size: {}...'.format(epochs, batch_size))
    if not test_only:
        model.load_state_dict(torch.load(back_model_save_path))
        best_valid_loss = float('inf')  # 初始化最佳验证损失
        no_improvement_count = 0  # 用于跟踪验证损失未改进的epoch数
        # 训练和验证
        for epoch in range(epochs):
            logger.info(f'Epoch {epoch + 1}/{epochs}')
            train_loss, train_precision, train_recall, train_f1 = train_or_evaluate(model, train_loader, optimizer,
                                                                                    scheduler, device, is_train=True)
            print(
                f'\tTrain Loss: {train_loss:.3f} | Train Precision: {train_precision:.2f} | Train Recall: {train_recall:.2f} | Train F1: {train_f1:.2f}')
            valid_loss, valid_precision, valid_recall, valid_f1 = train_or_evaluate(model, val_loader, optimizer,
                                                                                    scheduler,
                                                                                    device, is_train=False)

            print(
                f'\t Val. Loss: {valid_loss:.3f} |  Val Precision: {valid_precision:.2f} | Val Recall: {valid_recall:.2f} | Val F1: {valid_f1:.2f}')
            # 如果当前验证损失更低，保存模型
            if valid_loss < best_valid_loss:
                best_valid_loss = valid_loss
                no_improvement_count = 0  # 重置计数器
                logger.info('Validation loss improved, saving model...')
                torch.save(model.state_dict(), model_save_path)
                logger.info('Model saved.')
            else:
                no_improvement_count += 1
                logger.info(f'No improvement in validation loss for {no_improvement_count} epochs.')

            # 如果连续5个epoch没有改进，提前停止训练
            if no_improvement_count >= 3:
                logger.info('Early stopping triggered. Training stopped.')
                break

    # 测试
    logger.info('Model saved, starting test, loading model from {}...'.format(model_save_path))
    model.load_state_dict(torch.load(model_save_path))

    logger.info('Model loaded, starting test...')
    test_loss, test_precision, test_recall, test_f1 = train_or_evaluate(model, test_loader, optimizer, scheduler,
                                                                        device, is_train=False)
    print(
        f'\t Test. Loss: {test_loss:.3f} | Test Precision: {test_precision:.2f} | Test Recall: {test_recall:.2f} | Test F1: {test_f1:.2f}')
    logger.info('Testing complete, all done.')
