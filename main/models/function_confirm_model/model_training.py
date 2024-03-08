import torch
from transformers import AdamW, get_linear_schedule_with_warmup, RobertaTokenizer, RobertaForSequenceClassification

from main.interface import TrainDataItemForFunctionConfirmModel
from main.models.function_confirm_model.dataset_and_data_provider import create_datasets, create_dataloaders


def init_train(filepath,
               num_labels=2,
               model_name='microsoft/graphcodebert-base',
               token_max_length=512,
               batch_size=512,
               learn_rate=5e-5,
               epochs=3):
    """

    :param filepath: 训练数据json文件路径
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
    for special_token in TrainDataItemForFunctionConfirmModel.get_special_tokens():
        tokenizer.add_tokens(special_token)

    # model
    model = RobertaForSequenceClassification.from_pretrained(model_name, num_labels=num_labels).to(device)
    model.resize_token_embeddings(len(tokenizer))

    # datasets
    train_dataset, val_dataset, test_dataset = create_datasets(filepath, tokenizer, max_len=token_max_length)

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
    for batch in iterator:
        input_ids = batch['input_ids'].to(device)
        attention_mask = batch['attention_mask'].to(device)
        labels = batch['labels'].to(device)

        if is_train:
            optimizer.zero_grad()

        outputs = model(input_ids, attention_mask=attention_mask, labels=labels)

        loss = outputs[0]
        logits = outputs[1]

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
def run_train(filepath, epochs=3):
    # 初始化训练
    device, tokenizer, model, train_loader, val_loader, test_loader, optimizer, scheduler = init_train(filepath,
                                                                                                       epochs=epochs)
    # train scheduler
    for epoch in range(epochs):
        train_loss, train_acc = train_or_evaluate(model, train_loader, optimizer, scheduler, device, is_train=True)
        valid_loss, valid_acc = train_or_evaluate(model, val_loader, optimizer, scheduler, device, is_train=False)
        print(f'\tTrain Loss: {train_loss:.3f} | Train Acc: {train_acc * 100:.2f}%')
        print(f'\t Val. Loss: {valid_loss:.3f} |  Val. Acc: {valid_acc * 100:.2f}%')

    # 评估测试数据
    test_loss, test_acc = train_or_evaluate(model, test_loader, optimizer, scheduler, device, is_train=False)
    print(f'\t Test. Loss: {test_loss:.3f} |  Test. Acc: {test_acc * 100:.2f}%')


if __name__ == '__main__':
    data_file_path = r"C:\Users\liuchengyue\Desktop\projects\Wroks\v-conformer\TestCases\model_train\model_1\train_data\train_data.json"
    run_train(data_file_path)
