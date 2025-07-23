#!/bin/bash

# GetFiles 客户端-服务端构建脚本

echo "=== GetFiles 构建脚本 ==="

# 检查Go是否安装
if ! command -v go &> /dev/null; then
    echo "错误: 未找到Go编译器，请先安装Go 1.21或更高版本"
    exit 1
fi

# 检查Go版本
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
REQUIRED_VERSION="1.21"

if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "错误: 需要Go 1.21或更高版本，当前版本: $GO_VERSION"
    exit 1
fi

echo "Go版本: $GO_VERSION ✓"

# 构建服务端
echo ""
echo "=== 构建服务端 ==="
cd server

# 安装依赖
echo "安装服务端依赖..."
go mod tidy

# 编译服务端
echo "编译服务端..."
go build -o getfiles-server -ldflags="-s -w" .

if [ $? -eq 0 ]; then
    echo "服务端构建成功: server/getfiles-server"
else
    echo "服务端构建失败"
    exit 1
fi

cd ..

# 构建客户端
echo ""
echo "=== 构建客户端 ==="
cd client

# 安装依赖
echo "安装客户端依赖..."
go mod tidy

# 编译客户端
echo "编译客户端..."
go build -o getfiles-client -ldflags="-s -w" .

if [ $? -eq 0 ]; then
    echo "客户端构建成功: client/getfiles-client"
else
    echo "客户端构建失败"
    exit 1
fi

cd ..

echo ""
echo "=== 构建完成 ==="
echo ""
echo "可执行文件:"
echo "  服务端: ./server/getfiles-server"
echo "  客户端: ./client/getfiles-client"
echo ""
echo "使用方法:"
echo "  1. 启动服务端: cd server && ./getfiles-server"
echo "  2. 运行客户端: cd client && ./getfiles-client scan-and-upload"
echo "  3. 访问管理界面: http://localhost:8080"
echo "     管理密码: GetFiles@2025#Secure\$Admin!Complex&Password"
echo ""
echo "详细说明请查看 README.md" 