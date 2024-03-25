from environs import Env

env = Env()
env.read_env()

TREE_SITTER_LANGUAGE_FILE_PATH = env.str("TREE_SITTER_LANGUAGE_FILE_PATH", "Resources/build/my-languages-win.dll")
IDA_PRO_PATH = env.str("IDA_PRO_PATH", r"C:\Users\chengyue\Desktop\GreenPrograms\idapro75_51641\ida64.exe")
IDA_PRO_SCRIPT_PATH = env.str("IDA_PRO_SCRIPT_PATH",
                              r"C:\Users\chengyue\Desktop\projects\binary-v-confirmer\scripts\ida_scripts.py")
IDA_PRO_OUTPUT_PATH = env.str("IDA_PRO_OUTPUT_PATH",
                              r"C:\Users\chengyue\Desktop\projects\binary-v-confirmer\TestCases\feature_extraction\ida_pro_result.json")
