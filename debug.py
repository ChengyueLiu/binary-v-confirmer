from bintools.general.file_tool import load_from_json_file

bfs = load_from_json_file("TestCases/model_train/model_1/test_data/ida_pro_results/libcrypto.json")
print(len(bfs))