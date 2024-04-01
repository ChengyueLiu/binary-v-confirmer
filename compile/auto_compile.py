from bintools.general.file_tool import find_files_in_dir


def compile_file(file_path, binary_path):
    pass


def objdump(binary_path, objdump_path):
    pass


def extract_asm(objdump_path, asm_path):
    pass


def main():
    source_dir = 'src'
    binary_dir = 'bin'

    file_paths = find_files_in_dir(source_dir)
    for path in file_paths:
        for compiler in ['gcc', 'clang']:
            for opt in ['O0', 'O1', "O2", "O3"]:

                binary_path = binary_dir + '/' + path + '_' + compiler + '_' + opt
                compile_file(path, binary_path)
                objdump_path = binary_path + '.objdump'
                objdump(binary_path, objdump_path)
                asm_path = binary_path + '.asm'
                extract_asm(objdump_path, asm_path)
