from loguru import logger

from MODEL_1 import train_model_1
from MODEL_2 import train_model_2
from MODEL_3 import train_model_3

if __name__ == '__main__':
    logger.info("Start training model 1")
    train_model_1()
    logger.info("Start training model 2")
    train_model_2()
    logger.info("Start training model 3")
    train_model_3()
    logger.info("Training finished")
