from bintools.general.bin_tool import normalize_asm_code
from main.models.code_snippet_positioning_model_bigbird.model_application import SnippetPositioner_BB
from main.models.code_snippet_positioning_model_bigbird.model_training import run_train



def train_model_2():
    train_data_save_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    model_save_path = r"Resources/model_weights/model_2_weights_bigbird.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              model_save_path,
              test_only=False,
              epochs=3,
              batch_size=8,
              token_max_length=2048)


def test_model():
    src_codes = [
        "        BIO_puts(out, \"\\tThis Update: \");",
        "        ASN1_GENERALIZEDTIME_print(out, thisupd);",
        "        BIO_puts(out, \"\\n\");",
        "        BIO_puts(out, \"\\n\");",
        "        if (nextupd) {",
        "            BIO_puts(out, \"\\tNext Update: \");"
    ]
    asm_codes = [
        "   79cfa:\t48 8b 75 e0          \tmov    rsi,QWORD PTR [rbp-0x20]",
        "   79cfe:\t48 8b 45 d8          \tmov    rax,QWORD PTR [rbp-0x28]",
        "   79d02:\t48 8b 55 90          \tmov    rdx,QWORD PTR [rbp-0x70]",
        "   79d06:\t48 8b 4d 10          \tmov    rcx,QWORD PTR [rbp+0x10]",
        "   79d0a:\t48 89 c7             \tmov    rdi,rax",
        "   79d0d:\te8 ee 04 fd ff       \tcall   4a200 <OCSP_check_validity@plt>",
        "   79d12:\t85 c0                \ttest   eax,eax",
        "   79d14:\t75 1f                \tjne    79d35 <print_ocsp_summary+0x17f>",
        "   79d16:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d1a:\t48 8d 35 b7 f0 06 00 \tlea    rsi,[rip+0x6f0b7]        # e8dd8 <pedantic_opts+0x454c>",
        "   79d21:\t48 89 c7             \tmov    rdi,rax",
        "   79d24:\te8 67 e8 fc ff       \tcall   48590 <BIO_puts@plt>",
        "   79d29:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d2d:\t48 89 c7             \tmov    rdi,rax",
        "   79d30:\te8 1b b6 fc ff       \tcall   45350 <ERR_print_errors@plt>",
        "   79d35:\t8b 45 c0             \tmov    eax,DWORD PTR [rbp-0x40]",
        "   79d38:\t48 98                \tcdqe",
        "   79d3a:\t48 89 c7             \tmov    rdi,rax",
        "   79d3d:\te8 6e b9 fc ff       \tcall   456b0 <OCSP_cert_status_str@plt>",
        "   79d42:\t48 89 c2             \tmov    rdx,rax",
        "   79d45:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d49:\t48 8d 35 a8 f0 06 00 \tlea    rsi,[rip+0x6f0a8]        # e8df8 <pedantic_opts+0x456c>",
        "   79d50:\t48 89 c7             \tmov    rdi,rax",
        "   79d53:\tb8 00 00 00 00       \tmov    eax,0x0",
        "   79d58:\te8 53 0a fd ff       \tcall   4a7b0 <BIO_printf@plt>",
        "   79d5d:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d61:\t48 8d 35 94 f0 06 00 \tlea    rsi,[rip+0x6f094]        # e8dfc <pedantic_opts+0x4570>",
        "   79d68:\t48 89 c7             \tmov    rdi,rax",
        "   79d6b:\te8 20 e8 fc ff       \tcall   48590 <BIO_puts@plt>",
        "   79d70:\t48 8b 55 d8          \tmov    rdx,QWORD PTR [rbp-0x28]",
        "   79d74:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d78:\t48 89 d6             \tmov    rsi,rdx",
        "   79d7b:\t48 89 c7             \tmov    rdi,rax",
        "   79d7e:\te8 dd c9 fc ff       \tcall   46760 <ASN1_GENERALIZEDTIME_print@plt>",
        "   79d83:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79d87:\t48 8d 35 7d f0 06 00 \tlea    rsi,[rip+0x6f07d]        # e8e0b <pedantic_opts+0x457f>",
        "   79d8e:\t48 89 c7             \tmov    rdi,rax",
        "   79d91:\te8 fa e7 fc ff       \tcall   48590 <BIO_puts@plt>",
        "   79d96:\t48 8b 45 e0          \tmov    rax,QWORD PTR [rbp-0x20]",
        "   79d9a:\t48 85 c0             \ttest   rax,rax",
        "   79d9d:\t74 39                \tje     79dd8 <print_ocsp_summary+0x222>",
        "   79d9f:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79da3:\t48 8d 35 63 f0 06 00 \tlea    rsi,[rip+0x6f063]        # e8e0d <pedantic_opts+0x4581>",
        "   79daa:\t48 89 c7             \tmov    rdi,rax",
        "   79dad:\te8 de e7 fc ff       \tcall   48590 <BIO_puts@plt>",
        "   79db2:\t48 8b 55 e0          \tmov    rdx,QWORD PTR [rbp-0x20]",
        "   79db6:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79dba:\t48 89 d6             \tmov    rsi,rdx",
        "   79dbd:\t48 89 c7             \tmov    rdi,rax",
        "   79dc0:\te8 9b c9 fc ff       \tcall   46760 <ASN1_GENERALIZEDTIME_print@plt>",
        "   79dc5:\t48 8b 45 b8          \tmov    rax,QWORD PTR [rbp-0x48]",
        "   79dc9:\t48 8d 35 3b f0 06 00 \tlea    rsi,[rip+0x6f03b]        # e8e0b <pedantic_opts+0x457f>",
        "   79dd0:\t48 89 c7             \tmov    rdi,rax",
        "   79dd3:\te8 b8 e7 fc ff       \tcall   48590 <BIO_puts@plt>",
        "   79dd8:\t8b 45 c0             \tmov    eax,DWORD PTR [rbp-0x40]",
        "   79ddb:\t83 f8 01             \tcmp    eax,0x1",
        "   79dde:\t75 6b                \tjne    79e4b <print_ocsp_summary+0x295>"
    ]
    code_snippet_positioner = SnippetPositioner_BB(model_save_path="Resources/model_weights/model_2_weights.pth")
    question, predicted_answers = code_snippet_positioner.position("vul_function_name", src_codes, asm_codes)
    expected_answer = [ac.split("\t")[-1] for ac in asm_codes]
    expected_answer = [normalized_code for code in expected_answer if (normalized_code := normalize_asm_code(code))]
    print(" ".join(expected_answer[25:45]).strip())
    for pa in predicted_answers:
        print(pa.strip())


if __name__ == '__main__':
    # prepare_data()
    train_model_2()
    # test_model()