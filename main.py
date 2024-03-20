from bintools.general.file_tool import save_to_json_file
from main.VulConfirmTeam import VulConfirmTeam, confirm_vul
from main.interface import Vulnerability


def debug():
    binary_path = "TestCases/feature_extraction/binaries/libcrypto.so.3"
    vul = Vulnerability(
        project_name="openssl",
        file_path="TestCases/model_train/model_1/test_data/p12_add.c",
        function_name="*PKCS12_unpack_p7data"
    )
    save_path = "TestCases/confirm_results.json"

    confirm_vul(binary_path, vul, save_path)



if __name__ == '__main__':
    debug()
    # TODO
    #   1. 完整的代码跑通
    #   2. 逐个问题解决

    """
    1. O0如何确认漏洞
    2. O3如何确认漏洞
    3. 实现一个确认工具
    """
