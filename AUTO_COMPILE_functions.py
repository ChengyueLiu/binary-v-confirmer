import copy
import os
import subprocess
from multiprocessing import Pool

from loguru import logger
from tqdm import tqdm

from bintools.general.file_tool import find_files_in_dir, save_to_json_file
from bintools.general.src_tool import count_function_effective_lines
from main.extractors.function_feature_extractor import extract_src_feature_for_specific_function
from main.interface import SrcFunctionFeature, TrainFunction
from main.models.code_snippet_positioning_model.data_prepare import convert_mapping_to_json, get_src_lines, \
    get_snippet_position, get_correspond_save_path
from main.models.code_snippet_positioning_model.mapping_parser import MappingParser
from setting.settings import MODEL_1_TRAIN_DATA_SRC_CODE_MIN_NUM


def format_c_file(file_path):
    """
    使用clang-format格式化指定的C文件。

    参数:
    - file_path: 要格式化的C文件的路径。
    """
    try:
        # 构建命令
        command = ['clang-format', '-i', file_path]

        # 调用命令
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        print(f"格式化失败: {e}")
    except FileNotFoundError:
        print("错误: 未找到clang-format。请确保clang-format已安装并在PATH中。")


def format_all_c_files(root_source_dir):
    # 假设file_paths是已经找到的所有C文件路径的列表
    file_paths = find_files_in_dir(root_source_dir, file_extension='.c')

    # 使用所有可用核心的进程池
    with Pool(processes=os.cpu_count()) as pool:
        # 使用tqdm显示进度条
        list(tqdm(pool.imap_unordered(format_c_file, file_paths), total=len(file_paths), desc="formatting"))


def compile_c_file(c_file_path, binary_path, compiler="gcc", optimization_level='O0'):
    # 构建命令，包括调试信息和指定的优化等级
    command = [compiler,
               '-w',  # 不显示警告信息
               '-c', c_file_path,  # 编译源文件
               "-o", binary_path,  # 输出目标文件
               "-g",  # 生成调试信息
               f"-{optimization_level}"]  # 指定优化等级
    # print(f"command: {' '.join(command)}")
    try:
        # 调用GCC命令编译C文件
        subprocess.run(command, check=True)
    except subprocess.CalledProcessError as e:
        # 如果编译失败，打印错误信息
        logger.error(f"Compilation failed with the following error: {e}")


def objdump(binary_path, output_file_path):
    # objdump -d <source_path> --source --line-numbers -M intel > <target_path>
    command = [
        'objdump',
        '-d',  # 反汇编
        binary_path,  # 指定目标文件
        '--source',  # 显示源代码
        '--line-numbers',  # 显示行号
        '-M', 'intel'  # 指定Intel风格
    ]

    try:
        # Open the target file in write mode
        with open(output_file_path, 'w') as file:
            # Execute the objdump command and redirect the output to the target file
            subprocess.run(command, check=True, stdout=file, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Dump  failed with the following error: {e}")


def extract_asm(objdump_path, root_source_dir, asm_path):
    """
    TODO 提取汇编代码和源代码的对应关系，这里要批量提取
    """
    # parse functions
    parser = MappingParser()
    parser.parse(objdump_path)
    functions = copy.deepcopy(parser.functions)
    parser.reset()

    final_result = {}
    for function in functions:
        function_name = function["function_name"]
        sub_functions = function["sub_functions"]
        # 第一轮遍历，找到所有的源代码
        src_dict = get_src_lines(sub_functions, root_source_dir)

        # 第二轮编译
        sub_function_code_mappings = []
        for sub_function in sub_functions:
            sub_function_name = sub_function["function_name"]
            snippets = sub_function["snippets"]
            for snippet in snippets:
                # 相对位置信息
                real_file_path, line_number, is_discriminator = get_snippet_position(snippet, root_source_dir)

                # 汇编代码片段
                asm_lines = [line.split("\t")[-1] for line in snippet["asm_lines"]]

                # 源代码
                current_src_line = src_dict.get(sub_function_name, {})["src_codes"].get(line_number, None)
                if current_src_line is None:
                    continue

                sub_function_code_mappings.append({
                    "function_name": function_name,
                    "sub_function_name": sub_function_name,
                    "real_file_path": real_file_path,
                    "src_line_number": line_number,
                    "is_discriminator": is_discriminator,
                    "src_line": current_src_line,
                    "asm_lines": asm_lines,
                })
        final_result[function_name] = {
            "src_dict": src_dict,
            "asm_code_snippet_mappings": sub_function_code_mappings
        }
    save_to_json_file(final_result, asm_path)


def process_file(args):
    src_file_path, root_source_dir, root_binary_dir, compiler_list, opt_list = args
    base_binary_dir = src_file_path.replace(root_source_dir, root_binary_dir)
    os.makedirs(base_binary_dir, exist_ok=True)

    try:
        train_function = TrainFunction(src_file_path, base_binary_dir)

        # 提取源代码特征
        src_function_feature: SrcFunctionFeature = extract_src_feature_for_specific_function(
            src_file_path, train_function.function_name)

        if src_function_feature is None:
            return None

        if (src_line_num := count_function_effective_lines(
                src_function_feature.original_lines)) < MODEL_1_TRAIN_DATA_SRC_CODE_MIN_NUM:
            return None
        train_function.effective_src_line_num = src_line_num

        # save src feature
        save_to_json_file(src_function_feature.custom_serialize(), train_function.get_src_feature_path())

        # compile and extract asm codes
        for compiler in compiler_list:
            for opt in opt_list:
                # step 1: creat dir
                binary_dir = os.path.join(base_binary_dir, compiler, opt)
                os.makedirs(binary_dir, exist_ok=True)

                # step 2: compile c file
                binary_path = train_function.get_binary_path(compiler, opt)
                compile_c_file(src_file_path, binary_path, compiler, opt)

                # step 3: objdump
                dump_path = train_function.get_dump_path(compiler, opt)
                objdump(binary_path, dump_path)

                # step 4: extract asm
                asm_path = train_function.get_asm_path(compiler, opt)
                extract_asm(dump_path, root_source_dir, asm_path)

        return train_function
    except Exception as e:
        logger.error(f"{src_file_path} processing Error: {e}")
        return None


def main():
    root_source_dir = '/home/chengyue/projects/github_projects/AnghaBench'
    root_binary_dir = '/home/chengyue/projects/github_projects/compiled_AnghaBench'
    result_path = "test_results/compiled_paths.json"

    compiler_list = ['gcc', 'clang']
    opt_list = ['O0', 'O1', 'O2', 'O3']

    # 获取所有的C文件
    file_paths = find_files_in_dir(root_source_dir, file_extension='.c')

    # 多进程处理
    with Pool(processes=os.cpu_count()) as pool:
        args = [(c_file_path, root_source_dir, root_binary_dir, compiler_list, opt_list)
                for c_file_path in file_paths]

        # 使用tqdm显示进度
        train_functions = []
        for train_function in tqdm(pool.imap_unordered(process_file, args), total=len(args), desc="processing"):
            if train_function is None:
                continue
            train_functions.append(train_function)

    # 保存结果
    save_to_json_file([tf.customer_serialize() for tf in train_functions], result_path)


if __name__ == '__main__':
    # 格式化所有的代码，主要是解决代码风格不一致的问题，尤其是函数名定义。
    # format_all_c_files('/home/chengyue/projects/github_projects/AnghaBench')

    main()
