def prepare_data():
    """
    steps:
        1. 编译二进制文件，使用-g选项生成调试信息
        2. 使用objdump -d命令生成汇编代码，注意要使用 -M intel 选项, 以便生成Intel格式的汇编代码
        3. 把objdump生成的文件，转换成json格式
        4. 从json格式的文件中生成训练数据

    :return:
    """
    pass


def train_model():
    pass


def test_model():
    pass


if __name__ == '__main__':
    prepare_data()
