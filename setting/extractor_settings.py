#!/usr/bin/env python
# -*- coding: utf-8 -*-


# @Time : 2023/9/23 16:18
# @Author : Liu Chengyue
# @File : settings.py
# @Software: PyCharm
from environs import Env

env = Env()
env.read_env()

# 所有文件的大小总和限制，防止内存溢出
FEATURE_EXTRACTOR_MEMORY_LIMIT = 2048
# 计算commit time
CAL_COMMIT_TIME = env.bool("CAL_COMMIT_TIME", False)