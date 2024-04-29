import torch
from loguru import logger
from tqdm import tqdm
from transformers import AdamW, get_linear_schedule_with_warmup, RobertaTokenizer, RobertaForMultipleChoice

from main.interface import DataItemForCodeSnippetConfirmModelMC
from main.models.code_snippet_confirm_model_multi_choice.dataset_and_data_provider import create_dataloaders, \
    create_dataset


def init_train(train_data_json_file_path,
               val_data_json_file_path,
               test_data_json_file_path,
               num_labels=2,
               model_name='microsoft/graphcodebert-base',
               token_max_length=512,
               batch_size=512,
               learn_rate=5e-5,
               epochs=3):
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
    tokenizer = RobertaTokenizer.from_pretrained(model_name)
    for special_token in DataItemForCodeSnippetConfirmModelMC.get_special_tokens():
        tokenizer.add_tokens(special_token)

    # model
    model = RobertaForMultipleChoice.from_pretrained(model_name, num_labels=num_labels)
    model.resize_token_embeddings(len(tokenizer))
    model = torch.nn.DataParallel(model).to(device)

    # datasets
    train_dataset = create_dataset(train_data_json_file_path, tokenizer, token_max_length)
    val_dataset = create_dataset(val_data_json_file_path, tokenizer, token_max_length)
    test_dataset = create_dataset(test_data_json_file_path, tokenizer, token_max_length)

    # dataloader
    train_loader, val_loader, test_loader = create_dataloaders(train_dataset,
                                                               val_dataset,
                                                               test_dataset,
                                                               batch_size=batch_size)

    # optimizer
    optimizer = AdamW(model.parameters(), lr=learn_rate)

    total_steps = len(train_loader) * epochs
    scheduler = get_linear_schedule_with_warmup(optimizer, num_warmup_steps=0, num_training_steps=total_steps)
    return device, tokenizer, model, train_loader, val_loader, test_loader, optimizer, scheduler


# 定义训练和评估函数
def train_or_evaluate(model, iterator, optimizer, scheduler, device, is_train=True):
    if is_train:
        model.train()
    else:
        model.eval()

    epoch_loss = 0
    total_correct = 0
    total_instances = 0
    for batch in tqdm(iterator, desc="train_or_evaluate"):
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)

        if is_train:
            optimizer.zero_grad()

        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)

        loss = outputs.loss
        # 下面两行是为了适配多GPU训练
        if loss.dim() > 0:  # 如果损失不是标量
            loss = loss.mean()  # 计算所有损失的平均值确保是标量
        logits = outputs.logits

        if is_train:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)  # 适用于BERT的梯度裁剪
            optimizer.step()
            scheduler.step()  # 调用scheduler

        epoch_loss += loss.item()
        _, predicted_classes = torch.max(logits, dim=1)
        correct_predictions = (predicted_classes == labels).float()
        total_correct += correct_predictions.sum().item()
        total_instances += labels.size(0)

    epoch_acc = total_correct / total_instances
    return epoch_loss / len(iterator), epoch_acc


# 准备训练
def run_train(train_data_json_file_path,
              val_data_json_file_path,
              test_data_json_file_path,
              model_save_path_back_up="model_weights_back.pth",
              model_save_path="model_weights.pth",
              test_only=False,
              **kwargs):
    batch_size = kwargs.get('batch_size', 32)
    epochs = kwargs.get('epochs', 30)

    # 初始化训练
    logger.info('init train...')
    device, tokenizer, model, train_loader, val_loader, test_loader, optimizer, scheduler = init_train(
        train_data_json_file_path,
        val_data_json_file_path,
        test_data_json_file_path,
        batch_size=batch_size,
        epochs=epochs)
    if not test_only:
        if model_save_path_back_up:
            logger.info(f'load model state from {model_save_path}...')
            model.load_state_dict(torch.load(model_save_path))
            logger.info('model loaded.')
        logger.info('inited, start train, epochs: 3, batch_size: 32...')
        # train scheduler
        best_valid_loss = float('inf')  # 初始化最佳验证损失
        no_improvement_count = 0  # 用于跟踪验证损失未改进的epoch数
        for epoch in range(epochs):
            logger.info(f'Epoch {epoch + 1}/{epochs}')
            train_loss, train_acc = train_or_evaluate(model, train_loader, optimizer, scheduler, device, is_train=True)
            print(f'\tTrain Loss: {train_loss:.3f} | Train Acc: {train_acc * 100:.2f}%')
            valid_loss, valid_acc = train_or_evaluate(model, val_loader, optimizer, scheduler, device, is_train=False)
            print(f'\t Val. Loss: {valid_loss:.3f} |  Val. Acc: {valid_acc * 100:.2f}%')
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

    logger.info('load model from model_weights.pth...')
    model.load_state_dict(torch.load(model_save_path))

    logger.info('model loaded, start test...')
    test_loss, test_acc = train_or_evaluate(model, test_loader, optimizer, scheduler, device, is_train=False)
    print(f'\t Test. Loss: {test_loss:.3f} |  Test. Acc: {test_acc * 100:.2f}%')
    logger.info('test done, all done.')
