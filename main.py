from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.VulConfirmTeam import VulConfirmTeam, confirm_vul
from main.interface import CauseFunction


def train():
    from loguru import logger

    from MODEL_1 import train_model_1
    from MODEL_2 import train_model_2
    from MODEL_3 import train_model_3

    if __name__ == '__main__':
        logger.info("Start training model 1")
        # train_model_1()
        logger.info("Start training model 2")
        train_model_2()
        logger.info("Start training model 3")
        train_model_3()
        logger.info("Training finished")


def test_model():
    # Test model
    function_confirm_model_pth_path = r"Resources/model_weights/model_1_weights.pth"
    snippet_positioning_model_pth_path = r"Resources/model_weights/model_2_weights.pth"
    snippet_confirm_model_pth_path = r"Resources/model_weights/model_3_weights.pth"

    vul_confirm_team = VulConfirmTeam(
        function_confirm_model_pth_path=function_confirm_model_pth_path,
        snippet_positioning_model_pth_path=snippet_positioning_model_pth_path,
        snippet_confirm_model_pth_path=snippet_confirm_model_pth_path,
        batch_size=16
    )

    # Test vulnerability
    cause_function = CauseFunction(
        project_name="openssl",
        file_path="TestCases/model_train/model_1/test_data/p12_add.c",
        function_name="*PKCS12_unpack_p7data"
    )

    # test file: openssl
    binary_path = "TestCases/feature_extraction/binaries/openssl"
    save_path = "TestCases/openssl_confirm_results.json"
    confirm_vul(vul_confirm_team, binary_path, cause_function, save_path)

    # test file: libcrypto.so.3
    binary_path = "TestCases/feature_extraction/binaries/libcrypto.so.3"
    save_path = "TestCases/libcrypto_confirm_results.json"
    confirm_vul(vul_confirm_team, binary_path, cause_function, save_path)

    logger.info("Test finished")


if __name__ == '__main__':
    train()
    # test_model()
