from bintools.general.file_tool import save_to_json_file
from main.VulConfirmTeam import VulConfirmTeam, confirm_vul
from main.interface import Vulnerability


def train():
    from loguru import logger

    from MODEL_1 import train_model_1
    from MODEL_2 import train_model_2
    from MODEL_3 import train_model_3

    if __name__ == '__main__':
        logger.info("Start training model 1")
        train_model_1()
        logger.info("Start training model 2")
        train_model_2()
        logger.info("Start training model 3")
        train_model_3()
        logger.info("Training finished")


def test_model():
    binary_path = "TestCases/feature_extraction/binaries/libcrypto.so.3"
    binary_path = "TestCases/feature_extraction/binaries/openssl"
    vul = Vulnerability(
        project_name="openssl",
        file_path="TestCases/model_train/model_1/test_data/p12_add.c",
        function_name="*PKCS12_unpack_p7data"
    )
    save_path = "TestCases/confirm_results.json"

    confirm_vul(binary_path, vul, save_path)


if __name__ == '__main__':
    train()
    test_model()
