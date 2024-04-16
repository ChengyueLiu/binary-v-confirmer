import subprocess

from loguru import logger


def objdump(binary_path):
    # objdump -d <source_path> --source --line-numbers -M intel
    command = [
        'objdump',
        '-d',  # 反汇编
        binary_path,  # 指定目标文件
        '--source',  # 显示源代码
        '-M', 'intel'  # 指定Intel风格
    ]

    try:
        # 执行objdump命令，并捕获输出
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return result.stdout  # 返回标准输出的内容
    except subprocess.CalledProcessError as e:
        # 若命令执行失败，记录错误并返回空字符串或错误消息
        logger.error(f"Dump failed with the following error: {e.stderr}")
        return ""


def parse_asm_codes(binary_path):
    raw_lines = objdump(binary_path).split('\n')

    text_lines = []
    start = False
    for line in raw_lines:
        if line.startswith('Disassembly of section .text:'):
            start = True
            continue
        elif line.startswith('Disassembly of section .'):
            start = False
            continue

        if start:
            text_lines.append(line)

    asm_codes_dict = {}
    current_function_name = None
    for line in text_lines:
        if line.endswith('>:'):
            try:
                function_name = line.split(' <')[1][: -2]
            except:
                print(line)
                continue
            # function_name = line.split(' <')[1][: -2]
            current_function_name = function_name
            asm_codes_dict[function_name] = []
            continue

        if current_function_name is not None:
            line = line.split('\t')[-1]
            asm_codes_dict[current_function_name].append(line)

    return asm_codes_dict

