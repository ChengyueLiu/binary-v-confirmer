from main.models.code_snippet_positioning_model.data_prepare import convert_mapping_to_json, \
    convert_json_to_raw_train_data, convert_raw_train_data_to_train_data
from main.models.code_snippet_positioning_model.model_training import run_train


def prepare_data():
    """
    steps:
        1. 编译二进制文件，使用-g选项生成调试信息：使用autocompile 脚本
        2. 使用objdump -d命令生成汇编代码，注意要使用 -M intel 选项, 以便生成Intel格式的汇编代码：
            使用AutoDataPrepare脚本，这个脚本目前生成mapping文件是正常的，后续的功能可能还需要检查。
        3. 把objdump生成的文件，转换成json格式：这个使用NewMappingParser重新实现
        4. 从json格式的文件中生成训练数据：这个暂时还没实现

    :return:
    """

    original_mapping_files = "TestCases/model_train/model_2/original_mapping_files/"
    json_mapping_files = "TestCases/model_train/model_2/json_mapping_files"
    all_raw_train_data_items_dir = f"TestCases/model_train/model_2/raw_train_data_items"
    test_raw_train_data_items_dir = f"TestCases/model_train/model_2/raw_train_data_items/openssl/openssl-3.2.1/"
    train_data_json = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    valid_data_json = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    test_data_json = "TestCases/model_train/model_2/final_train_data_items/test_data.json"

    # step 3: mapping ---> json
    # convert_mapping_to_json(original_mapping_files, json_mapping_files)

    # step 4: json ---> raw train data：每一行源代码和汇编代码的对应关系
    # convert_json_to_raw_train_data(json_mapping_files, all_raw_train_data_items_dir)

    # step 5: raw train data ---> train data
    # TODO 现在模型的输入可能非常长，汇编代码肯定是要截断的。怎么个截断策略？
    #   先不考虑那些比例很奇怪的数据
    convert_raw_train_data_to_train_data(test_raw_train_data_items_dir,
                                         train_data_json,
                                         valid_data_json,
                                         test_data_json)


def train_model():
    train_data_save_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    model_save_path = "model_weights/model_2_weights.pth"
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
    train_model()
