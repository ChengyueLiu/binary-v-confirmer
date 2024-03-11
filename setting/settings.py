from environs import Env

env = Env()
env.read_env()

# Github
GITHUB_TOKEN = env.str("GITHUB_TOKEN")