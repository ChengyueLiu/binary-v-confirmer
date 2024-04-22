from main.models.code_snippet_confirm_model_multi_choice.data_prepare import generate_data_items
from main.models.code_snippet_confirm_model_multi_choice.model_application import SnippetChoicer
from main.models.code_snippet_confirm_model_multi_choice.model_training import run_train


def prepare_data():
    """
    steps:
        1. model_2 的数据作为正例，model_2 的数据相互交叉，作为负例

    :return:
    """
    # train
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/train_data.json"
    generate_data_items(input_file_path, save_file_path)

    # valid
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/valid_data.json"
    generate_data_items(input_file_path, save_file_path)

    # test
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/test_data.json"
    generate_data_items(input_file_path, save_file_path)


def train_model_3():
    train_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/train_data_items_for_model_3.json"
    val_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/val_data_items_for_model_3.json"
    test_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/test_data_items_for_model_3.json"
    model_save_path = "Resources/model_weights/model_3_weights.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              model_save_path,
              test_only=False,
              epochs=30,
              batch_size=48)





if __name__ == '__main__':
    # prepare_data()
    train_model_3()
