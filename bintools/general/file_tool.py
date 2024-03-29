import hashlib
import json
import os
from loguru import logger


def check_dir_path(dir_path):
    """
    check if the dir_path exists and is a directory

    :param dir_path: a directory path
    :return: a normalized and absolute path
    """
    if not os.path.exists(dir_path):
        error_msg = f"Directory not found: {dir_path}, create it first."
        raise FileNotFoundError(error_msg)
    if not os.path.isdir(dir_path):
        raise NotADirectoryError(f"{dir_path} is not a directory.")
    return os.path.normpath(os.path.abspath(dir_path))


def check_file_path(file_path, extension=None):
    """
    check if the file_path belongs to a valid dir and has a .json extension
    :param file_path: a file path
    :return: a normalized and absolute path
    """
    file_path = os.path.normpath(os.path.abspath(file_path))
    dir_path, file_name = os.path.split(file_path)
    dir_path = check_dir_path(dir_path)

    if extension:
        pure_name, ext = os.path.splitext(file_name)
        if not ext:
            raise ValueError(f"File name should have an extension: {file_name}")

        if ext != extension:
            raise ValueError(f"File extension should be {extension}: {file_name}")

    file_path = os.path.normpath(os.path.abspath(os.path.join(dir_path, file_name)))
    return file_path


def find_files_in_dir(dir_path: str, file_extension: str):
    """
    在目录中找出所有指定后缀的文件
    :param dir_path:
    :param file_extension:
    :return:
    """
    logger.info(f"Finding all mapping files in {dir_path}")

    file_paths = []
    for root, dirs, files in os.walk(dir_path):
        for file in files:
            if file.endswith(file_extension):
                file_paths.append(os.path.join(root, file))

    logger.info(f"Found {len(file_paths)} {file_extension} files")
    return file_paths


def load_from_json_file(file_path, encoding='utf-8', output_log=False):
    file_path = check_file_path(file_path, '.json')

    if output_log:
        logger.info(f"Loading data from {file_path}")

    with open(file_path, 'r', encoding=encoding) as f:
        data = json.load(f)

    if output_log:
        logger.info(f"Data loaded to {file_path}")

    return data


def save_to_json_file(data, file_path, encoding='utf-8', output_log=False):
    """
    save data to a json file
    set output_log to True to print the file path

    :param data:
    :param file_path:
    :param encoding:
    :param output_log:
    :return:
    """
    file_path = check_file_path(file_path, '.json')

    if output_log:
        logger.info(f"Saving data to {file_path}")

    with open(file_path, 'w', encoding=encoding) as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    if output_log:
        logger.info(f"Data saved to {file_path}")


def calculate_file_md5(file_path):
    """计算文件的SHA-256哈希值"""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()
