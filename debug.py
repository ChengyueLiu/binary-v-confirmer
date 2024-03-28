import difflib
from typing import List

from bintools.general.bin_tool import normalize_asm_code
from main.interface import SpecialToken

asm_codes_1 = [
            "endbr64",
            "sub     rsp, 8",
            "xor     edx, edx",
            "xor     ecx, ecx",
            "mov     esi, 0Dh",
            "call    _BIO_ctrl",
            "xor     edx, edx",
            "test    rax, rax",
            "cmovs   rax, rdx",
            "add     rsp, 8",
            "xor     edx, edx",
            "xor     ecx, ecx",
            "xor     esi, esi",
            "xor     edi, edi",
            "retn"
        ]
asm_codes_2 = [
            "endbr64",
            "xor     eax, eax",
            "cmp     qword ptr [rdi+38h], 0",
            "jz      short loc_228598",
            "xor     esi, esi",
            "xor     edi, edi",
            "retn",
            "mov     [rdi+38h], rsi",
            "mov     eax, 1",
            "xor     esi, esi",
            "xor     edi, edi",
            "retn"
        ]

def this_normalize_asm_code(asm_codes):
    return [normalized_code for code in asm_codes
            if (normalized_code := normalize_asm_code(code,
                                                      reg_token=SpecialToken.ASM_REG.value,
                                                      num_token=SpecialToken.ASM_NUM.value,
                                                      jump_token=SpecialToken.ASM_JUMP.value,
                                                      loc_token=SpecialToken.ASM_LOC.value,
                                                      mem_token=SpecialToken.ASM_MEM.value))]
def levenshtein_distance(asm_codes_1:List[str], asm_codes_2:List[str]):
    s1 = " ".join(this_normalize_asm_code(asm_codes_1[:20]))
    s2 = " ".join(this_normalize_asm_code(asm_codes_2[:20]))

    return difflib.SequenceMatcher(None, s1, s2).ratio()


print("Levenshtein Distance:", levenshtein_distance(asm_codes_1, asm_codes_2))