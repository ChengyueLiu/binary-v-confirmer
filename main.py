from loguru import logger

from bintools.general.file_tool import save_to_json_file
from main.VulConfirmTeam import VulConfirmTeam, confirm_vul
from main.interface import CauseFunction, Vulnerability, Patch


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
    # cause_function
    cause_function = CauseFunction(
        project_name="openssl",
        file_name="crypto/pkcs12/p12_add.c",
        file_path="TestCases/model_train/model_1/test_data/p12_add.c",
        function_name="*PKCS12_unpack_p7data"
    )

    # patch
    patch = Patch(
        commit_link="https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        commit_api="https://api.github.com/repos/openssl/openssl/commits/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        fixed_in="3.2.1",
        affected_since="3.2.0",

        start_line_before_commit=78,
        snippet_size_before_commit=6,
        snippet_codes_before_commit=[
            "         ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA);",
            "         return NULL;",
            "     }",
            "     return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS),",
            "                                ossl_pkcs7_ctx_get0_libctx(&p7->ctx),",
            "                                ossl_pkcs7_ctx_get0_propq(&p7->ctx));"
        ],
        start_line_after_commit=78,
        snippet_size_after_commit=12,
        snippet_codes_after_commit=[
            "         ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA);",
            "         return NULL;",
            "     }",
            "+",
            "+    if (p7->d.data == NULL) {",
            "+        ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR);",
            "+        return NULL;",
            "+    }",
            "+",
            "     return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS),",
            "                                ossl_pkcs7_ctx_get0_libctx(&p7->ctx),",
            "                                ossl_pkcs7_ctx_get0_propq(&p7->ctx));"
        ],
    )

    # vulnerability
    vulnerability = Vulnerability(
        cve_id="CVE-2024-0727",
        cve_link="https://www.cve.org/CVERecord?id=CVE-2024-0727",
        title="PKCS12 Decoding crashes",
        severity="Low",
        cause_function=cause_function,
        patches=[patch]
    )
    vul_confirm_team = VulConfirmTeam(batch_size=100)

    # openssl
    binary_path = "TestCases/model_train/model_1/test_data/openssl"
    save_path = "openssl_confirm_results.json"
    analysis = vul_confirm_team.confirm(binary_path=binary_path, vul=vulnerability)
    save_to_json_file(analysis.customer_serialize(), save_path, output_log=True)

    # openssl
    binary_path = "TestCases/model_train/model_1/test_data/libcrypto.so.3"
    save_path = "libcrypto_confirm_results.json"
    analysis = vul_confirm_team.confirm(binary_path=binary_path, vul=vulnerability)
    save_to_json_file(analysis.customer_serialize(), save_path, output_log=True)


if __name__ == '__main__':
    train()
    test_model()
