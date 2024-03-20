from main.models.code_snippet_confirm_model.data_prepare import generate_data_items
from main.models.code_snippet_confirm_model.model_training import run_train


def prepare_data():
    """
    steps:
        1. model_2 的数据作为正例，model_2 的数据相互交叉，作为负例

    :return:
    """
    # train
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/train_data.json"
    generate_data_items(input_file_path, save_file_path)

    # valid
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/valid_data.json"
    generate_data_items(input_file_path, save_file_path)

    # test
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/test_data.json"
    generate_data_items(input_file_path, save_file_path)


def train_model_3():
    train_data_save_path = "TestCases/model_train/model_3/data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_3/data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_3/data_items/test_data.json"
    model_save_path = "model_weights/model_3_weights.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              model_save_path,
              epochs=3,
              batch_size=64)


def test_model():
    pass


if __name__ == '__main__':
    # prepare_data()
    train_model_3()
    # test_model()
