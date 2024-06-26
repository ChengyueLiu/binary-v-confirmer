#!/usr/bin/env python
# -*- coding: utf-8 -*-


# @Time : 2023/10/24 14:16
# @Author : Liu Chengyue
# @File : generate_treesitter_languages..py
# @Software: PyCharm

from tree_sitter import Language

from setting.paths import TREE_SITTER_LANGUAGE_FILE_PATH

# When using on windows, Microsoft Visual C++ 14.0 or greater is required. Get it with "Microsoft C++ Build Tools": https://visualstudio.microsoft.com/visual-cpp-build-tools/
Language.build_library(
    # Store the library in the `build` directory
    # 'resources/build/my-languages-mac.so',
    TREE_SITTER_LANGUAGE_FILE_PATH,

    # Include one or more languages
    [
        'vendor/tree-sitter-c',
        'vendor/tree-sitter-cpp'
    ]
)
