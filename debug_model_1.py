from loguru import logger

from main.models.function_confirm_model.data_prepare import convert_function_feature_to_train_data
from main.models.function_confirm_model.model_application import find_similar_functions, VulFunctionFinder


def debug_convert_function_feature_to_train_data():
    """
    调试提取特征的整个流程
    :return:
    """
    function_feature_path = r"TestCases/feature_extraction/function_features.json"
    save_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    convert_function_feature_to_train_data(function_feature_path, save_path, negative_ratio=3)

    # data = load_from_json_file(function_feature_path)
    #
    # function_feature = FunctionFeature.init_from_dict(data[333])
    # train_data_item = TrainDataItemForModel1(function_feature)
    # save_to_json_file(train_data_item.custom_serialize(), save_path)


def debug_model_application():
    """
    测试模型的应用

    :return:
    """
    # src file
    vul_function_file_path = r"/home/chengyue/projects/binary-v-confirmer/TestCases/model_train/model_1/test_data/p12_add.c"

    # vul function name
    vul_function_name = "*PKCS12_unpack_p7data"

    # binary file
    openssl = r"/home/chengyue/projects/binary-v-confirmer/TestCases/model_train/model_1/test_data/openssl"
    libcrypto = r"/home/chengyue/projects/binary-v-confirmer/TestCases/model_train/model_1/test_data/libcrypto.so.3"
    libssl = r"/home/chengyue/projects/binary-v-confirmer/TestCases/model_train/model_1/test_data/libssl.so.3"

    # model init
    model_save_path = r"/home/chengyue/projects/binary-v-confirmer/model_weights.pth"
    batch_size = 64

    vul_function_finder = VulFunctionFinder(
        model_save_path=model_save_path,
        batch_size=batch_size
    )
    for binary in [openssl, libcrypto, libssl]:
        logger.info(f"Finding similar functions for {vul_function_name} in {binary}")
        vul_function_finder.find_similar_functions(src_file_path=vul_function_file_path,
                                                   vul_function_name=vul_function_name,
                                                   binary_file_abs_path=binary)
    logger.info(f"Done")


def train_model_1():
    """
    训练模型1, 这个不是一个调试函数，而是一个可用的训练函数

    :return:
    """
    from main.models.function_confirm_model.model_training import run_train
    data_file_path = r"TestCases/model_train/model_1/train_data/train_data.json"
    run_train(data_file_path, epochs=3, batch_size=16)


if __name__ == '__main__':
    # debug_convert_function_feature_to_train_data()
    # train_model_1()
    debug_model_application()
