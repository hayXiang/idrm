#!/bin/bash

# 准备iOS兼容测试环境
echo "准备iOS兼容测试环境..."

# 确保WASM文件存在
if [ ! -f "main.wasm" ]; then
    echo "编译WASM模块..."
    GOOS=js GOARCH=wasm go build -o main.wasm main.go
fi

# 复制WASM执行脚本（如果不存在）
if [ ! -f "wasm_exec.js" ]; then
    echo "复制wasm_exec.js..."
    cp "$(go env GOROOT)/misc/wasm/wasm_exec.js" .
fi

echo "iOS兼容测试环境准备完成！"
echo "请在Web服务器环境下打开 ios-compatible-test.html 文件进行测试。"