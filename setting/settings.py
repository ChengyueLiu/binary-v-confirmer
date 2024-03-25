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
POSSIBLE_BIN_FUNCTION_TOP_N = env.int("POSSIBLE_BIN_FUNCTION_TOP_N", 10)
