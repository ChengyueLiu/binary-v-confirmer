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
        snippet_asm_codes_after_commit=[
            "  36544f:\te8 de c0 ea ff       \tcall   211532 <ERR_new>",
            "  365454:\t48 8d 15 95 9f 18 00 \tlea    rdx,[rip+0x189f95]        # 4ef3f0 <__func__.19847>",
            "  36545b:\tbe 4e 00 00 00       \tmov    esi,0x4e",
            "  365460:\t48 8d 3d 29 9f 18 00 \tlea    rdi,[rip+0x189f29]        # 4ef390 <__func__.21698+0x18>",
            "  365467:\te8 14 c1 ea ff       \tcall   211580 <ERR_set_debug>",
            "  36546c:\tba 00 00 00 00       \tmov    edx,0x0",
            "  365471:\tbe 79 00 00 00       \tmov    esi,0x79",
            "  365476:\tbf 23 00 00 00       \tmov    edi,0x23",
            "  36547b:\tb8 00 00 00 00       \tmov    eax,0x0",
            "  365480:\te8 4e c1 ea ff       \tcall   2115d3 <ERR_set_error>",
            "  365485:\tb8 00 00 00 00       \tmov    eax,0x0",
            "  36548a:\te9 8e 00 00 00       \tjmp    36551d <PKCS12_unpack_p7data+0xf6>",
            "  36548f:\t48 8b 45 e8          \tmov    rax,QWORD PTR [rbp-0x18]",
            "  365493:\t48 8b 40 20          \tmov    rax,QWORD PTR [rax+0x20]",
            "  365497:\t48 85 c0             \ttest   rax,rax",
            "  36549a:\t75 3d                \tjne    3654d9 <PKCS12_unpack_p7data+0xb2>",
            "  36549c:\te8 91 c0 ea ff       \tcall   211532 <ERR_new>",
            "  3654a1:\t48 8d 15 48 9f 18 00 \tlea    rdx,[rip+0x189f48]        # 4ef3f0 <__func__.19847>",
            "  3654a8:\tbe 53 00 00 00       \tmov    esi,0x53",
            "  3654ad:\t48 8d 3d dc 9e 18 00 \tlea    rdi,[rip+0x189edc]        # 4ef390 <__func__.21698+0x18>",
            "  3654b4:\te8 c7 c0 ea ff       \tcall   211580 <ERR_set_debug>",
            "  3654b9:\tba 00 00 00 00       \tmov    edx,0x0",
            "  3654be:\tbe 65 00 00 00       \tmov    esi,0x65",
            "  3654c3:\tbf 23 00 00 00       \tmov    edi,0x23",
            "  3654c8:\tb8 00 00 00 00       \tmov    eax,0x0",
            "  3654cd:\te8 01 c1 ea ff       \tcall   2115d3 <ERR_set_error>",
            "  3654d2:\tb8 00 00 00 00       \tmov    eax,0x0",
            "  3654d7:\teb 44                \tjmp    36551d <PKCS12_unpack_p7data+0xf6>",
            "  3654d9:\t48 8b 45 e8          \tmov    rax,QWORD PTR [rbp-0x18]",
            "  3654dd:\t48 83 c0 28          \tadd    rax,0x28",
            "  3654e1:\t48 89 c7             \tmov    rdi,rax",
            "  3654e4:\te8 22 ce 00 00       \tcall   37230b <ossl_pkcs7_ctx_get0_propq>",
            "  3654e9:\t49 89 c4             \tmov    r12,rax",
            "  3654ec:\t48 8b 45 e8          \tmov    rax,QWORD PTR [rbp-0x18]",
            "  3654f0:\t48 83 c0 28          \tadd    rax,0x28",
            "  3654f4:\t48 89 c7             \tmov    rdi,rax",
            "  3654f7:\te8 ec cd 00 00       \tcall   3722e8 <ossl_pkcs7_ctx_get0_libctx>",
            "  3654fc:\t48 89 c3             \tmov    rbx,rax",
            "  3654ff:\te8 e3 09 00 00       \tcall   365ee7 <PKCS12_SAFEBAGS_it>",
            "  365504:\t48 89 c6             \tmov    rsi,rax",
            "  365507:\t48 8b 45 e8          \tmov    rax,QWORD PTR [rbp-0x18]",
            "  36550b:\t48 8b 40 20          \tmov    rax,QWORD PTR [rax+0x20]",
            "  36550f:\t4c 89 e1             \tmov    rcx,r12",
            "  365512:\t48 89 da             \tmov    rdx,rbx",
            "  365515:\t48 89 c7             \tmov    rdi,rax",
            "  365518:\te8 be fb d7 ff       \tcall   e50db <ASN1_item_unpack_ex>",
            "  36551d:\t48 83 c4 10          \tadd    rsp,0x10",
            "  365521:\t5b                   \tpop    rbx",
            "  365522:\t41 5c                \tpop    r12",
            "  365524:\t5d                   \tpop    rbp",
            "  365525:\tc3                   \tret",
        ]
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
    vul_confirm_team = VulConfirmTeam(batch_size=64)

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
