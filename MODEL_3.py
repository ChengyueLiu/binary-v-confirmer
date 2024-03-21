from main.models.code_snippet_confirm_model.data_prepare import generate_data_items
from main.models.code_snippet_confirm_model.model_application import SnippetConfirmer
from main.models.code_snippet_confirm_model.model_training import run_train


def prepare_data():
    """
    steps:
        1. model_2 的数据作为正例，model_2 的数据相互交叉，作为负例

    :return:
    """
    # train
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/train_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/train_data.json"
    generate_data_items(input_file_path, save_file_path)

    # valid
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/valid_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/valid_data.json"
    generate_data_items(input_file_path, save_file_path)

    # test
    input_file_path = "TestCases/model_train/model_2/final_train_data_items/test_data.json"
    save_file_path = "TestCases/model_train/model_3/data_items/test_data.json"
    generate_data_items(input_file_path, save_file_path)


def train_model_3():
    train_data_save_path = "TestCases/model_train/model_3/data_items/train_data.json"
    val_data_save_path = "TestCases/model_train/model_3/data_items/valid_data.json"
    test_data_save_path = "TestCases/model_train/model_3/data_items/test_data.json"
    model_save_path = "model_weights/model_3_weights.pth"
    run_train(train_data_save_path,
              val_data_save_path,
              test_data_save_path,
              model_save_path,
              test_only=False,
              epochs=3,
              batch_size=100)


def test_model():
    src_codes_text = "STACK_OF(PKCS12_SAFEBAG) *PKCS12_unpack_p7data(PKCS7 *p7) { if (!PKCS7_type_is_data(p7)) { ERR_raise(ERR_LIB_PKCS12, PKCS12_R_CONTENT_TYPE_NOT_DATA); return NULL; } if (p7->d.data == NULL) { ERR_raise(ERR_LIB_PKCS12, PKCS12_R_DECODE_ERROR); return NULL; } return ASN1_item_unpack_ex(p7->d.data, ASN1_ITEM_rptr(PKCS12_SAFEBAGS), ossl_pkcs7_ctx_get0_libctx(&p7->ctx), ossl_pkcs7_ctx_get0_propq(&p7->ctx)); }",
    asm_codes_text_list = [
            "endbr64 push <REG> mov <REG>,<REG> sub <REG>,110h mov [<REG>+write_p],edi mov [<REG>+version],esi mov [<REG>+content_type],edx mov [<REG>+buf],<REG> mov [<REG>+len],<REG> mov [<REG>+ssl],<REG> mov <REG>,[<REG>+arg_0] mov [<REG>+arg],<REG> mov <REG>,fs:28h mov [<REG>+var_8],<REG> xor eax,eax mov <REG>,[<REG>+arg] mov [<REG>+bio],<REG> cmp [<REG>+write_p],<NUM> <JUMP> short loc_cf05a lea <REG>,asc_106c75 <JUMP> short loc_cf061 lea <REG>,asc_106c79 mov [<REG>+str_write_p],<REG> lea <REG>,unk_106c7d mov [<REG>+str_content_type],<REG> lea <REG>,unk_106c7d mov [<REG>+str_details1],<REG> lea <REG>,unk_106c7d mov [<REG>+str_details2],<REG> mov <REG>,[<REG>+buf] mov [<REG>+bp_0],<REG>",
            "<JUMP> short loc_cf061 lea <REG>,asc_106c79 mov [<REG>+str_write_p],<REG> lea <REG>,unk_106c7d mov [<REG>+str_content_type],<REG> lea <REG>,unk_106c7d mov [<REG>+str_details1],<REG> lea <REG>,unk_106c7d mov [<REG>+str_details2],<REG> mov <REG>,[<REG>+buf] mov [<REG>+bp_0],<REG> cmp [<REG>+version],300h <JUMP> short loc_cf0f8 cmp [<REG>+version],301h <JUMP> short loc_cf0f8 cmp [<REG>+version],302h <JUMP> short loc_cf0f8 cmp [<REG>+version],303h <JUMP> short loc_cf0f8 cmp [<REG>+version],304h <JUMP> short loc_cf0f8 cmp [<REG>+version],0feffh <JUMP> short loc_cf0f8 cmp [<REG>+version],100h <JUMP> loc_cf30f mov eax,[<REG>+version] lea <REG>,def lea <REG>,ssl_versions mov edi,eax call lookup mov [<REG>+str_version],<REG>",
            "<JUMP> short loc_cf0f8 cmp [<REG>+version],0feffh <JUMP> short loc_cf0f8 cmp [<REG>+version],100h <JUMP> loc_cf30f mov eax,[<REG>+version] lea <REG>,def lea <REG>,ssl_versions mov edi,eax call lookup mov [<REG>+str_version],<REG>",
            "<JUMP> loc_cf2a1 cmp [<REG>+content_type],17h <JUMP> loc_cf2d1 cmp [<REG>+content_type],16h <JUMP> loc_cf24c cmp [<REG>+content_type],16h <JUMP> loc_cf2d1 cmp [<REG>+content_type],14h <JUMP> short loc_cf1a5 cmp [<REG>+content_type],15h <JUMP> short loc_cf1b8 <JUMP> loc_cf2d1 lea <REG>,achangeciphersp mov [<REG>+str_content_type],<REG> <JUMP> loc_cf30d lea <REG>,aalert mov [<REG>+str_content_type],<REG> lea <REG>,asc_106c9d mov [<REG>+str_details1],<REG> cmp [<REG>+len],<NUM> <JUMP> loc_cf309 mov <REG>,[<REG>+bp_0] movzx eax,[<REG>] movzx eax,al cmp eax,<NUM> <JUMP> short loc_cf1fb cmp eax,<NUM> <JUMP> short loc_cf20b <JUMP> short loc_cf21a lea <REG>,awarning_0 mov [<REG>+str_details1],<REG> <JUMP> short loc_cf21a lea <REG>,afatal mov [<REG>+str_details1],<REG> nop",
            "lea <REG>,alert_types mov edi,eax call lookup mov [<REG>+str_details2],<REG> <JUMP> loc_cf309 lea <REG>,ahandshake mov [<REG>+str_content_type],<REG> lea <REG>,def mov [<REG>+str_details1],<REG> cmp [<REG>+len],<NUM> <JUMP> loc_cf30c mov <REG>,[<REG>+bp_0] movzx eax,[<REG>] movzx eax,al lea <REG>,def lea <REG>,handshakes mov edi,eax call lookup mov [<REG>+str_details1],<REG> <JUMP> short loc_cf30c lea <REG>,aapplicationdat mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d lea <REG>,arecordheader mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d lea <REG>,ainnercontent mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d mov edx,[<REG>+content_type] lea <REG>,[<REG>+tmpbuf] mov ecx,edx lea <REG>,aunknowncontent mov esi,7fh mov <REG>,<REG> mov eax,<NUM>",
            "lea <REG>,aapplicationdat mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d lea <REG>,arecordheader mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d lea <REG>,ainnercontent mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf30d mov edx,[<REG>+content_type] lea <REG>,[<REG>+tmpbuf] mov ecx,edx lea <REG>,aunknowncontent mov esi,7fh mov <REG>,<REG> mov eax,<NUM> call _bio_snprintf lea <REG>,[<REG>+tmpbuf] mov [<REG>+str_content_type],<REG> <JUMP> short loc_cf34e nop <JUMP> short loc_cf34e nop <JUMP> short loc_cf34e mov ecx,[<REG>+content_type] mov edx,[<REG>+version] lea <REG>,[<REG>+tmpbuf] mov <REG>,ecx mov ecx,edx lea <REG>,anottlsdataorun mov esi,7fh mov <REG>,<REG> mov eax,<NUM>",
            "nop <JUMP> short loc_cf34e nop <JUMP> short loc_cf34e mov ecx,[<REG>+content_type] mov edx,[<REG>+version] lea <REG>,[<REG>+tmpbuf] mov <REG>,ecx mov ecx,edx lea <REG>,anottlsdataorun mov esi,7fh mov <REG>,<REG> mov eax,<NUM> call _bio_snprintf lea <REG>,[<REG>+tmpbuf] mov [<REG>+str_version],<REG> mov <REG>,[<REG>+len] mov <REG>,[<REG>+str_content_type] mov <REG>,[<REG>+str_version] mov <REG>,[<REG>+str_write_p] mov <REG>,[<REG>+bio] push [<REG>+str_details2] push [<REG>+str_details1] mov <REG>,<REG> mov <REG>,<REG> lea <REG>,assslength04lxs mov <REG>,<REG> mov eax,<NUM> call _bio_printf add <REG>,10h cmp [<REG>+len],<NUM> <JUMP> loc_cf4a3 mov <REG>,[<REG>+bio] lea <REG>,asc_106d72 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+len] mov [<REG>+num],<REG> mov [<REG>+i],<NUM> <JUMP> short loc",
            "mov <REG>,[<REG>+bio] push [<REG>+str_details2] push [<REG>+str_details1] mov <REG>,<REG> mov <REG>,<REG> lea <REG>,assslength04lxs mov <REG>,<REG> mov eax,<NUM> call _bio_printf add <REG>,10h cmp [<REG>+len],<NUM> <JUMP> loc_cf4a3 mov <REG>,[<REG>+bio] lea <REG>,asc_106d72 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+len] mov [<REG>+num],<REG> mov [<REG>+i],<NUM> <JUMP> short loc_cf44d mov <REG>,[<REG>+i] and eax,0fh test <REG>,<REG> <JUMP> short loc_cf413 cmp [<REG>+i],<NUM> <JUMP> short loc_cf413 mov <REG>,[<REG>+bio] lea <REG>,asc_106d76 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+buf] mov <REG>,[<REG>+i] add <REG>,<REG> movzx eax,[<REG>] movzx edx,al mov <REG>,[<REG>+bio] lea <REG>,a02x_6 mov <REG>,<REG> mov eax,<NUM>",
            "and eax,0fh test <REG>,<REG> <JUMP> short loc_cf413 cmp [<REG>+i],<NUM> <JUMP> short loc_cf413 mov <REG>,[<REG>+bio] lea <REG>,asc_106d76 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+buf] mov <REG>,[<REG>+i] add <REG>,<REG> movzx eax,[<REG>] movzx edx,al mov <REG>,[<REG>+bio] lea <REG>,a02x_6 mov <REG>,<REG> mov eax,<NUM> call _bio_printf add [<REG>+i],<NUM> mov <REG>,[<REG>+i] cmp <REG>,[<REG>+num] <JUMP> short loc_cf3df mov <REG>,[<REG>+i] cmp <REG>,[<REG>+len] jnb short loc_cf488 mov <REG>,[<REG>+bio] lea <REG>,asc_106d81 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+bio] lea <REG>,asc_1062a2 mov <REG>,<REG> mov eax,<NUM> call _bio_printf mov <REG>,[<REG>+bio] mov ecx,<NUM> mov edx,<NUM> mov esi,0bh mov <REG>,<REG> call _bio_ctrl nop"
        ]
    result = SnippetConfirmer(
        model_save_path="Resources/model_weights/model_3_weights.pth",
        batch_size=16
    ).confirm_vuls(src_codes_text, asm_codes_text_list)
    print(result)


if __name__ == '__main__':
    # prepare_data()
    train_model_3()
    test_model()
