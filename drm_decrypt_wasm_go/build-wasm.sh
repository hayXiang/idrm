#!/bin/bash
set -e

echo "Building WebAssembly module..."

# 检查是否安装了Go
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed or not in PATH"
    exit 1
fi

# 检查Go版本
GO_VERSION=$(go version | grep -o 'go1\.[0-9]*')
if [[ $GO_VERSION =~ ^go1\.([0-9]+)$ ]] && [ ${BASH_REMATCH[1]} -lt 18 ]; then
    echo "Error: Go version 1.18 or higher is required for WebAssembly support"
    exit 1
fi

# 复制wasm_exec.js到当前目录（Go自带的）
# 首先尝试新版本的路径，然后是旧版本的路径
WASM_EXEC_NEW_PATH=$(go env GOROOT)/lib/wasm/wasm_exec.js
WASM_EXEC_OLD_PATH=$(go env GOROOT)/misc/wasm/wasm_exec.js

if [ -f "$WASM_EXEC_NEW_PATH" ]; then
    cp "$WASM_EXEC_NEW_PATH" .
    echo "Copied wasm_exec.js from Go installation (new path)"
elif [ -f "$WASM_EXEC_OLD_PATH" ]; then
    cp "$WASM_EXEC_OLD_PATH" .
    echo "Copied wasm_exec.js from Go installation (old path)"
else
    echo "Error: Could not find wasm_exec.js at $WASM_EXEC_NEW_PATH or $WASM_EXEC_OLD_PATH"
    exit 1
fi