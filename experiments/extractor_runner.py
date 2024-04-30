import multiprocessing

from loguru import logger
from tqdm import tqdm

from main.extractors.bin_function_feature_extractor.objdump_parser import parse_objdump_file


def parse_objdump_file_wrapper(file_path):
    """
    提取汇编函数
    """
    asm_function_dict = parse_objdump_file(file_path, ignore_warnings=True)
    return file_path, asm_function_dict


def generate_asm_function_cache(test_cases):
    """
    多进程提取汇编函数，生成缓存dict

    {
        file_path: {
            function_name: List[AsmFunction]
        }
    }
    """
    path_set = set()
    for tc in test_cases:
        path_set.add(tc.test_bin.binary_path)

    paths = list(path_set)

    cache_dict = {}
    with multiprocessing.Pool(multiprocessing.cpu_count() - 6) as pool:
        results = list(tqdm(pool.imap_unordered(parse_objdump_file_wrapper, paths), total=len(paths),
                            desc="generate_asm_function_cache"))

    for path, asm_function_dict in results:
        cache_dict[path] = asm_function_dict

    return cache_dict


def extract_asm_functions(test_bin, asm_functions_cache=None):
    if asm_functions_cache and test_bin.binary_path in asm_functions_cache:
        asm_function_dict = asm_functions_cache[test_bin.binary_path]
    else:
        asm_function_dict = parse_objdump_file(test_bin.binary_path, ignore_warnings=True)
        asm_functions_cache[test_bin.binary_path] = asm_function_dict
    return asm_function_dict
