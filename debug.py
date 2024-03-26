import random

def modify_list(str_list):
    # 创建列表的副本，以便进行修改
    modified_list = str_list.copy()
    # 计算随机位置的数量，1-3
    num_positions = random.randint(1, 3)

    for _ in range(num_positions):
        if modified_list:  # 确保列表不为空
            # 选择一个随机位置
            pos = random.randint(0, len(modified_list) - 1)
            # 随机选择删除或插入
            action = random.choice(['delete', 'insert'])
            if action == 'delete':
                # 执行删除操作
                del modified_list[pos]
            else:
                # 执行插入操作
                # 随机选择一个字符串来插入
                string_to_insert = random.choice(str_list)
                modified_list.insert(pos + 1, string_to_insert)

    return modified_list

# 示例使用
str_list = ["line 1", "line 2", "line 3", "line 4"]
modified_list = modify_list(str_list)
print("Original List:", str_list)
print("Modified List:", modified_list)
