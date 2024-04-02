from environs import Env
from loguru import logger

env = Env()
env.read_env()

# Github
GITHUB_TOKEN = env.str("GITHUB_TOKEN", "")
if not GITHUB_TOKEN:
    logger.warning("GITHUB_TOKEN is not set. You may encounter rate limiting issues.")

# Cause Function Similarity Threshold
CAUSE_FUNCTION_SIMILARITY_THRESHOLD = env.float("CAUSE_FUNCTION_SIMILARITY_THRESHOLD", 0.95)
POSSIBLE_BIN_FUNCTION_TOP_N = env.int("POSSIBLE_BIN_FUNCTION_TOP_N", 1)

# ------------ Model 1 ------------

# TODO 重新整理这些参数
# ----- 训练数据准备 -----
# 训练数据源代码有效代码最小行数
MODEL_1_TRAIN_DATA_SRC_CODE_MIN_NUM = env.int("MODEL_1_TRAIN_DATA_SRC_CODE_MIN_NUM", 5)
# 训练数据汇编码最小行数
MODEL_1_TRAIN_DATA_ASM_CODE_MIN_NUM = env.int("MODEL_1_TRAIN_DATA_ASM_CODE_MIN_NUM", 10)


# ----- 特征生成 -----
# 汇编代码不超过35行
SRC_CODE_NUM = env.int("SRC_CODE_NUM", 13)

# 汇编代码不超过35行
ASM_CODE_NUM = env.int("ASM_CODE_NUM", 40)

