from bintools.general.file_tool import save_to_json_file
from main.VulConfirmTeam import VulConfirmTeam
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
    # patch
    patch_1 = Patch(
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

    # cause_function
    cause_function_1 = CauseFunction(
        project_name="openssl",
        file_name="crypto/pkcs12/p12_add.c",
        file_path="TestCases/cve/p12_add.c",
        function_name="*PKCS12_unpack_p7data",
        patches=[patch_1]
    )
    # patch
    patch_2 = Patch(
        commit_link="https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        commit_api="https://api.github.com/repos/openssl/openssl/commits/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        fixed_in="3.2.1",
        affected_since="3.2.0",

        start_line_before_commit=80,
        snippet_size_before_commit=8,
        snippet_codes_before_commit=[
            "             bags = PKCS12_unpack_p7data(p7);",
            "         } else if (bagnid == NID_pkcs7_encrypted) {",
            "             bags = PKCS12_unpack_p7encdata(p7, oldpass, -1);",
            "-            if (!alg_get(p7->d.encrypted->enc_data->algorithm,",
            "-                         &pbe_nid, &pbe_iter, &pbe_saltlen, &cipherid))",
            "                 goto err;",
            "         } else {",
            "             continue;"
        ],
        start_line_after_commit=80,
        snippet_size_after_commit=9,
        snippet_codes_after_commit=[
            "             bags = PKCS12_unpack_p7data(p7);",
            "         } else if (bagnid == NID_pkcs7_encrypted) {",
            "             bags = PKCS12_unpack_p7encdata(p7, oldpass, -1);",
            "+            if (p7->d.encrypted == NULL",
            "+                    || !alg_get(p7->d.encrypted->enc_data->algorithm,",
            "+                                &pbe_nid, &pbe_iter, &pbe_saltlen, &cipherid))",
            "                 goto err;",
            "         } else {",
            "             continue;"
        ],
    )

    # cause_function
    cause_function_2 = CauseFunction(
        project_name="openssl",
        file_name="crypto/pkcs12/p12_npas.c",
        file_path="TestCases/cve/p12_npas.c",
        function_name="newpass_p12",
        patches=[patch_2]
    )
    # patch
    patch_3 = Patch(
        commit_link="https://github.com/openssl/openssl/commit/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        commit_api="https://api.github.com/repos/openssl/openssl/commits/775acfdbd0c6af9ac855f34969cdab0c0c90844a",
        fixed_in="3.2.1",
        affected_since="3.2.0",

        start_line_before_commit=33,
        snippet_size_before_commit=10,
        snippet_codes_before_commit=[
            "     int ctype_nid = OBJ_obj2nid(p7->type);",
            "     const PKCS7_CTX *ctx = ossl_pkcs7_get0_ctx(p7);",
            " ",
            "-    if (ctype_nid == NID_pkcs7_signed)",
            "         mdalgs = p7->d.sign->md_algs;",
            "-    else",
            "         mdalgs = NULL;",
            " ",
            "     flags ^= SMIME_OLDMIME;",
            " "
        ],
        start_line_after_commit=33,
        snippet_size_after_commit=13,
        snippet_codes_after_commit=[
            "     int ctype_nid = OBJ_obj2nid(p7->type);",
            "     const PKCS7_CTX *ctx = ossl_pkcs7_get0_ctx(p7);",
            " ",
            "+    if (ctype_nid == NID_pkcs7_signed) {",
            "+        if (p7->d.sign == NULL)",
            "+            return 0;",
            "         mdalgs = p7->d.sign->md_algs;",
            "+    } else {",
            "         mdalgs = NULL;",
            "+    }",
            " ",
            "     flags ^= SMIME_OLDMIME;",
            " "
        ],
    )

    # cause_function
    cause_function_3 = CauseFunction(
        project_name="openssl",
        file_name="crypto/pkcs7/pk7_mime.c",
        file_path="TestCases/cve/pk7_mime.c",
        function_name="SMIME_write_PKCS7",
        patches=[patch_3]
    )

    # vulnerability
    vulnerability = Vulnerability(
        cve_id="CVE-2024-0727",
        cve_link="https://www.cve.org/CVERecord?id=CVE-2024-0727",
        title="PKCS12 Decoding crashes",
        severity="Low",
        cause_functions=[cause_function_1, cause_function_2, cause_function_3]
    )
    vul_confirm_team = VulConfirmTeam(batch_size=100)

    # openssl 3.2.1
    openssl_320 = "TestCases/binaries/openssl_3.2.0/openssl"
    libcrypto_320 = "TestCases/binaries/openssl_3.2.0/libcrypto.so.3"
    libssl_320 = "TestCases/binaries/openssl_3.2.0/libssl.so.3"
    openssl_321 = "TestCases/binaries/openssl_3.2.1/openssl"
    libcrypto_321 = "TestCases/binaries/openssl_3.2.1/libcrypto.so.3"
    libssl_321 = "TestCases/binaries/openssl_3.2.1/libssl.so.3"
    libpng16 = "TestCases/binaries/libpng/libpng16.so.16.43.0"

    save_path = "test_results/openssl_320_result.json"
    vul_confirm_team.confirm(binary_path=openssl_320, vul=vulnerability)
    save_to_json_file(vulnerability.customer_serialize(), save_path, output_log=True)

    save_path = "test_results/libpng_16_result.json"
    vul_confirm_team.confirm(binary_path=libpng16, vul=vulnerability)
    save_to_json_file(vulnerability.customer_serialize(), save_path, output_log=True)

    save_path = "test_results/libcrypto_321_result.json"
    vul_confirm_team.confirm(binary_path=libcrypto_321, vul=vulnerability)
    save_to_json_file(vulnerability.customer_serialize(), save_path, output_log=True)


if __name__ == '__main__':
    # train()
    test_model()
