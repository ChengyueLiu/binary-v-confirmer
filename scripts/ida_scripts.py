import idautils
import ida_funcs
import idc
import ida_auto  # 导入ida_auto模块
import json

SAVE_PATH = r"C:\Users\liuchengyue\Desktop\projects\Wroks\v-conformer\TestCases\feature_extraction\ida_pro_result.json"  # 请根据需要修改路径


def get_functions_info():
    functions_list = []

    # 遍历所有函数
    for func_ea in idautils.Functions():
        func_info = {}
        func_name = ida_funcs.get_func_name(func_ea)
        func_asm_codes = []
        func_strings = []
        func_immediates = []

        # 获取函数的汇编代码
        for ins in idautils.FuncItems(func_ea):
            func_asm_codes.append(idc.GetDisasm(ins))

            # 检查指令中的每个操作数
            for op in range(0, 2):  # 大多数指令最多两个操作数，如果需要可以增加
                op_type = idc.get_operand_type(ins, op)
                # 字符串和立即数检测逻辑
                if op_type == idc.o_imm:  # 立即数
                    func_immediates.append(idc.get_operand_value(ins, op))
                elif op_type == idc.o_mem or op_type == idc.o_far or op_type == idc.o_near:  # 内存引用，可能是字符串
                    op_value = idc.get_operand_value(ins, op)
                    string = idc.get_strlit_contents(op_value)
                    if string:
                        func_strings.append(string.decode('utf-8'))

        # 去重复的字符串和立即数
        func_strings = list(set(func_strings))
        func_immediates = list(set(func_immediates))

        # 保存函数名、汇编代码、字符串和立即数到字典中
        func_info['name'] = func_name
        func_info['asm_codes'] = func_asm_codes
        func_info['strings'] = func_strings
        func_info['numbers'] = func_immediates

        # 将字典添加到列表中
        functions_list.append(func_info)

    # 写入到JSON文件
    with open(SAVE_PATH, 'w') as json_file:
        json.dump(functions_list, json_file, indent=4)


def main():
    ida_auto.auto_wait()  # 确保自动分析完成
    get_functions_info()
    print("Done!")  # 打印提示信息
    idc.qexit(0)  # 确保执行完毕后IDA退出


if __name__ == '__main__':
    main()
