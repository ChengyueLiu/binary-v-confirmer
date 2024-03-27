from main.models.code_snippet_confirm_model_multi_choice.data_prepare import generate_data_items
from main.models.code_snippet_confirm_model_multi_choice.model_application import SnippetChoicer
from main.models.code_snippet_confirm_model_multi_choice.model_training import run_train


def prepare_data():
    """
    steps:
        1. model_2 的数据作为正例，model_2 的数据相互交叉，作为负例

    :return:
    """
    # train
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/train_data.json"
    generate_data_items(input_file_path, save_file_path)

    # valid
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/valid_data.json"
    generate_data_items(input_file_path, save_file_path)

    # test
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    save_file_path = "TestCases/model_train/model_3_multi_choice/data_items/test_data.json"
    generate_data_items(input_file_path, save_file_path)


def train_model_3():
    train_data_save_path = "TestCases/model_train/model_3_multi_choice/data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_3_multi_choice/data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_3_multi_choice/data_items/test_data.json"
    model_save_path = "Resources/model_weights/model_3_weights_MC.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              model_save_path,
              test_only=False,
              epochs=3,
              batch_size=48)


def test_model():
    asm_code_text = ' call _ERR_new lea rdx,aPkcs12UnpackP7_1 mov esi,4Eh lea rdi,aCryptoPkcs12P1 call _ERR_set_debug xor eax,eax xor edx,edx mov esi,79h mov edi,23h call _ERR_set_error xor eax,eax pop rbx xor edx,edx xor esi,esi xor edi,edi ret'

    src_code_before_commit = 'ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA); return NULL; } return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), ossl_pkcs7_ctx_get0_libctx(&p7->ctx), ossl_pkcs7_ctx_get0_propq(&p7->ctx));'

    src_code_after_commit = 'ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA); return NULL; } if (p7->d.data == NULL) { ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR); return NULL; } return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), ossl_pkcs7_ctx_get0_libctx(&p7->ctx), ossl_pkcs7_ctx_get0_propq(&p7->ctx));'
    result = SnippetChoicer(
        model_save_path="Resources/model_weights/model_3_weights_MC.pth",
        batch_size=16).choice(asm_code_texts=[asm_code_text],
                              vul_src_code_text=src_code_before_commit,
                              patch_src_code_text=src_code_after_commit)
    print(result)


if __name__ == '__main__':
    # prepare_data()
    # train_model_3()
    test_model()
