import os

from bintools.general.file_tool import save_to_json_file
from main.extractors.function_feature_extractor import extract_bin_feature


def pre_extract_bin_func_features(bin_dir, root_save_dir):
    bin_dir = os.path.abspath(bin_dir)
    root_save_dir = os.path.abspath(root_save_dir)
    for root, dirs, files in os.walk(bin_dir):
        for f in files:
            if ".json" in f or "i64" in f:
                continue
            f_path = os.path.abspath(os.path.join(root, f))
            save_path = f_path.replace(bin_dir, root_save_dir) + '.json'
            save_dir = os.path.dirname(save_path)
            os.makedirs(save_dir, exist_ok=True)
            bin_function_features = extract_bin_feature(f_path)
            print(f_path)
            print(save_path)
            save_to_json_file([bff.custom_serialize() for bff in bin_function_features], save_path)

if __name__ == '__main__':
    bin_dir = 'TestCases/binaries/self_compiled'
    save_dir = 'TestCases/binary_function_features/self_compiled'
    pre_extract_bin_func_features(bin_dir, save_dir)
