from tqdm import tqdm
from transformers import AutoTokenizer

from bintools.general.file_tool import load_from_json_file
from bintools.general.normalize import normalize_src_lines, normalize_asm_lines
from main.interface import DataItemForCodeSnippetPositioningModel, AsmFunction

model_name = 'microsoft/graphcodebert-base'


def init_tokenizer():
    tokenizer = AutoTokenizer.from_pretrained(model_name, use_fast=True)
    for special_token in DataItemForCodeSnippetPositioningModel.get_special_tokens():
        tokenizer.add_tokens(special_token)
    return tokenizer


def cal_token_length(question: str, context: str, tokenizer):
    encoding = tokenizer.encode_plus(
        question,
        context,
        add_special_tokens=True,
        # max_length=512,
        # padding='max_length',
        # truncation=True,
        return_attention_mask=True,
        return_offsets_mapping=True,  # 需要offsets来计算答案位置
        return_tensors='pt',
    )
    token_length = len(encoding['input_ids'][0])
    return token_length


def _load_asm_function_dict_from_file(asm_functions_save_path):
    asm_function_items_dict = load_from_json_file(asm_functions_save_path)
    asm_function_dict = {}
    for library, library_asm_function_items_dict in tqdm(asm_function_items_dict.items(), desc='init asm functions'):
        if library not in asm_function_dict:
            asm_function_dict[library] = {}
        for tag, asm_function_item_list in library_asm_function_items_dict.items():
            if tag not in asm_function_dict[library]:
                asm_function_dict[library][tag] = []
            for asm_function_item in asm_function_item_list:
                asm_function = AsmFunction.init_from_dict(asm_function_item)
                asm_function_dict[library][tag].append(asm_function)
    return asm_function_dict





if __name__ == '__main__':
    asm_codes = ['mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rax', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov eax,<MEM>',
                 'cdqe', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'add rax,rdx', 'mov eax,<MEM>', 'cmp <MEM>,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rax', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x10000', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov rsi,<MEM>', 'mov ecx,<MEM>', 'mov edx,<MEM>', 'mov r9,rsi', 'mov r8d,ecx',
                 'mov ecx,edx', 'lea rdx,<MEM>', 'mov esi,0x30', 'mov rdi,rax', 'mov eax,0x0', 'call <av_log>',
                 'mov rax,<MEM>', 'add rax,0xd0', 'mov rdi,rax', 'call <pthread_mutex_lock@plt>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov <MEM>,rax', 'cmp <MEM>,0x0', '<JUMP> <LOC>', 'mov eax,<MEM>',
                 'cdqe', 'lea rdx,<MEM>', 'mov rax,<MEM>', 'add rax,rdx', 'mov eax,<MEM>', 'cmp <MEM>,eax',
                 '<JUMP> <LOC>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov rax,<MEM>', 'mov <MEM>,rax', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov eax,<MEM>', 'and eax,0x10000', 'test eax,eax', '<JUMP> <LOC>', 'mov rax,<MEM>',
                 'mov rax,<MEM>', 'mov rsi,<MEM>', 'mov ecx,<MEM>', 'mov edx,<MEM>', 'mov r9,rsi', 'mov r8d,ecx']
    question = ""
    context = " ".join(asm_codes)
    tokenizer = init_tokenizer()

    asm_function_dict = _load_asm_function_dict_from_file(
        '/home/chengyue/projects/RESEARCH_DATA/test_cases/bin_vul_confirm_tcs/asm_functions_tmp.json')
    length_list = []
    for library, library_asm_function_dict in asm_function_dict.items():
        for tag, asm_function_list in library_asm_function_dict.items():
            for asm_function in asm_function_list:
                all_asm_codes, src_code_start_line = asm_function.get_asm_codes(skip_function_def=True)
                all_asm_codes = all_asm_codes[:70]
                context = " ".join(normalize_asm_lines(all_asm_codes))
                for i in range(len(asm_function.code_mappings) - 2):
                    src_codes = []
                    asm_codes = []
                    code_mappings = asm_function.code_mappings[i:i + 3]
                    for code_mapping in code_mappings:
                        if not code_mapping.asm_codes or not code_mapping.src_codes:
                            continue
                        src_codes.append(code_mapping.src_codes[-1])
                        asm_codes.extend(code_mapping.asm_codes)
                    question = " ".join(normalize_src_lines(src_codes))

                    token_length = cal_token_length(question, context, tokenizer)
                    length_list.append(token_length)

                    print(len(src_codes))
                    print(len(asm_codes))
                    print(len(all_asm_codes))
                    print(token_length)
                    print()

    print(max(length_list))
    print(min(length_list))
    print(sum(length_list) / len(length_list))
