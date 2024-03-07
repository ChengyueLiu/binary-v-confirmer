import idautils
import ida_funcs
import idc
import json

SVAE_PATH = r"C:\Users\liuchengyue\Desktop\projects\Wroks\v-conformer\TestCases\feature_extraction\openssl_bin_feature.json"


def get_functions_info():
    functions_list = []

    # 遍历所有函数
    for func_ea in idautils.Functions():
        func_info = {}
        func_name = ida_funcs.get_func_name(func_ea)
        func_asm_codes = []

        # 获取函数的汇编代码
        for ins in idautils.FuncItems(func_ea):
            func_asm_codes.append(idc.generate_disasm_line(ins, 0))

        # 保存函数名和汇编代码到字典中
        func_info['name'] = func_name
        func_info['assembly'] = func_asm_codes

        # 将字典添加到列表中
        functions_list.append(func_info)

    # 写入到JSON文件
    with open(SVAE_PATH, 'w') as json_file:
        json.dump(functions_list, json_file, indent=4)


if __name__ == '__main__':
    # 执行函数
    get_functions_info()
