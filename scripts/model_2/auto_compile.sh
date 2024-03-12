#!/bin/bash

# 脚本说明
# 这个脚本用于编译openssl项目
# 参数说明
# $1: 项目名称 (目前只支持openssl)
# $2: 可选的tag名字，如果提供，则先切换到这个tag，如果没提供使用"no_tag"

PROJECT=$1
TAG=${2:-no_tag}

# 基础输出位置
BASE_DIR="/home/chengyue/test_cases/binary_sca_vul_confirmation/compiled_projects"
BASE_OUTPUT_DIR="$BASE_DIR/$PROJECT/$TAG"

# OpenSSL源代码备份目录
OPENSSL_BACKUP_DIR="/home/chengyue/test_cases/binary_sca_vul_confirmation/github_projects/openssl-backup" # 请确保这是正确的备份目录路径

# 确保OpenSSL源代码备份目录存在
if [ ! -d "$OPENSSL_BACKUP_DIR" ]; then
    echo "OpenSSL backup directory does not exist: $OPENSSL_BACKUP_DIR"
    exit 1
fi

# 删除当前的OpenSSL目录并从备份复制新的OpenSSL目录
if [ "$PROJECT" = "openssl" ]; then
    echo "Preparing OpenSSL directory for tag $TAG..."
    rm -rf "$PROJECT"  # 删除当前的openssl目录
    cp -r "$OPENSSL_BACKUP_DIR" "./$PROJECT"  # 从备份复制新的openssl目录
else
    echo "Project $PROJECT is not supported by this script."
    exit 1
fi

# 切换到基础目录
cd "$PROJECT" || exit

# 如果提供了tag参数且不是"no_tag"，则切换到这个tag
if [ "$TAG" != "no_tag" ]; then
    echo "Checking out to tag $TAG..."
    git checkout "$TAG" || exit
fi


# 编译前的准备
make clean 2>/dev/null || echo "Skipping make clean for $PROJECT"

for OPT_LEVEL in 0 1 2 3; do
    OUTPUT_DIR="$BASE_OUTPUT_DIR/O$OPT_LEVEL/"
    mkdir -p "$OUTPUT_DIR"

    echo "Compiling $PROJECT with tag $TAG and optimization level -O$OPT_LEVEL..."

    # 为当前优化级别设置环境变量
    CONFIGURE_FLAGS="--prefix=$OUTPUT_DIR"
    export CFLAGS="-O$OPT_LEVEL -g -ggdb3"
    export CXXFLAGS="-O$OPT_LEVEL -g -ggdb3"

    # 配置项目
    if [ -f "./config" ]; then
        ./config $CONFIGURE_FLAGS
    elif [ -f "./Configure" ]; then
        ./Configure $CONFIGURE_FLAGS
    else
        echo "No suitable configuration script found"
        continue  # 跳过当前循环
    fi

    # 编译和安装
    make -j
    make install_sw || { echo "make install_sw failed, attempting make install"; make install; }

    echo "$PROJECT with tag $TAG and optimization level -O$OPT_LEVEL has been compiled and installed to $OUTPUT_DIR."

    make clean 2>/dev/null || echo "Cleaning up after build"
done

echo "Compilation for all tags and optimization levels completed."
