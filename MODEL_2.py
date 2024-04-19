from random import shuffle

from loguru import logger

from bintools.general.file_tool import load_from_json_file
from main.interface import TrainFunction
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
    all_raw_train_data_items_dir = f"TestCases/model_train/model_2/raw_train_data_items/openssl"
    test_raw_train_data_items_dir = f"TestCases/model_train/model_2/raw_train_data_items/openssl/openssl-3.2.1/"
    train_data_json = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    valid_data_json = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    test_data_json = "TestCases/model_train/model_2/final_train_data_items/test_data.json"

    # step 3: mapping ---> json
    convert_mapping_to_json(original_mapping_files, json_mapping_files)

    # step 4: json ---> raw train data：每一行源代码和汇编代码的对应关系
    convert_json_to_raw_train_data(json_mapping_files, all_raw_train_data_items_dir)

    # step 5: raw train data ---> train data
    convert_raw_train_data_to_train_data(test_raw_train_data_items_dir,
                                         train_data_json,
                                         valid_data_json,
                                         test_data_json)


def prepare_train_data_for_model_2_new():
    train_data_save_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"

    # 加载TrainFunction json数据
    logger.info(f"loading train functions from json file...")
    train_functions_json_items = load_from_json_file("test_results/compiled_paths.json")
    shuffle(train_functions_json_items)

    # 转换成TrainFunction对象
    logger.info(f"converting json items to TrainFunction objects...")
    train_functions = [TrainFunction.init_from_dict(item) for item in train_functions_json_items]
    for tf in train_functions:
        if "openssl" in tf.function_save_path:
            print(tf.function_save_path, tf.function_name)
    # # 筛选数据
    # # shuffle and split
    # logger.info(f"shuffling and splitting...")
    # train_functions, valid_functions, test_functions = shuffle_and_split(train_functions)
    #
    # # train data
    # train_data_items = []
    # for tf in tqdm(train_functions,desc="generating train data"):
    #     data_item = tf.generate_model_2_train_data_item()
    #     if data_item is None:
    #         continue
    #     train_data_items.append(data_item)
    # save_to_json_file(train_data_items, train_data_save_path)
    #
    # # valid data
    # valid_data_items = []
    # for tf in tqdm(valid_functions,desc="generating valid data"):
    #     data_item = tf.generate_model_2_train_data_item()
    #     if data_item is None:
    #         continue
    #     valid_data_items.append(data_item)
    # save_to_json_file(valid_data_items, val_data_save_path)
    #
    # # train data
    # test_data_items = []
    # for tf in tqdm(test_functions, desc="generating test data"):
    #     data_item = tf.generate_model_2_train_data_item()
    #     if data_item is None:
    #         continue
    #     test_data_items.append(data_item)
    # save_to_json_file(test_data_items, test_data_save_path)


def train_model_2():
    # train_data_items
    train_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/train_data_items_for_model_2.json"
    val_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/val_data_items_for_model_2.json"
    test_data_save_path = r"/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/test_data_items_for_model_2.json"

    back_model_save_path = r"Resources/model_weights/model_2_weights_back.pth"
    model_save_path = r"Resources/model_weights/model_2_weights.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              back_model_save_path=back_model_save_path,
              model_save_path=model_save_path,
              test_only=False,
              epochs=30,
              batch_size=80)


if __name__ == '__main__':
    # prepare_data()
    # prepare_train_data_for_model_2_new()
    train_model_2()
