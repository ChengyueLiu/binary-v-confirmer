from environs import Env

env = Env()
env.read_env()

TREE_SITTER_LANGUAGE_FILE_PATH = env.str("TREE_SITTER_LANGUAGE_FILE_PATH", "Resources/build/my-languages-mac.dll")
IDA_PRO_PATH = r"C:\Users\liuchengyue\GreenPrograms\idapro75_51641\ida64.exe"
IDA_PRO_SCRIPT_PATH = r"C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer\scripts\ida_scripts.py"
IDA_PRO_OUTPUT_PATH = r"C:\Users\liuchengyue\Desktop\projects\Wroks\binary-v-confirmer\TestCases\feature_extraction\ida_pro_result.json"
