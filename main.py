from main.VulConfirmTeam import VulConfirmTeam
from main.interface import Vulnerability


def debug():
    function_confirm_model_pth_path = r"Resources/model_weights/model_1_weights.pth"
    snippet_positioning_model_pth_path = r"Resources/model_weights/model_2_weights.pth"
    snippet_confirm_model_pth_path = r"Resources/model_weights/model_3_weights.pth"
    vul_confirm_team = VulConfirmTeam(
        function_confirm_model_pth_path=function_confirm_model_pth_path,
        snippet_positioning_model_pth_path=snippet_positioning_model_pth_path,
        snippet_confirm_model_pth_path=snippet_confirm_model_pth_path,
        batch_size=16
    )

    binary_path = "TestCases/feature_extraction/binaries/libcrypto.so.3"
    vul = Vulnerability(
        project_name="openssl",
        file_path="TestCases/model_train/model_1/test_data/p12_add.c",
        function_name="*PKCS12_unpack_p7data"
    )

    results = vul_confirm_team.confirm(binary_path=binary_path, vul=vul)


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
