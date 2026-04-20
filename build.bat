@echo off
setlocal enabledelayedexpansion

:: 设置基础变量
set BIN_NAME=idrm
set REMOTE_DEST=root@public.hxiang.eu.org:/mnt/data/local-disk1/public/idrm/
set PORT=60112

echo Starting Go build process...

:: 1. Android arm64
echo Building for Android...
set CGO_ENABLED=0
set GOOS=android
set GOARCH=arm64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

:: 2. Linux arm64
echo Building for Linux arm64...
set GOOS=linux
set GOARCH=arm64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

:: 3. Linux amd64
echo Building for Linux amd64...
set GOARCH=amd64
go build -o %BIN_NAME%-%GOOS%-%GOARCH%

:: 4. Windows amd64
echo Building for Windows...
set GOOS=windows
set GOARCH=amd64
go build -o %BIN_NAME%.exe

:: 执行上传
echo Uploading to server...
:: 注意：Windows 下 scp 同样支持 -P 参数（需安装 OpenSSH 客户端）
scp -P %PORT% %BIN_NAME%-android-arm64 %BIN_NAME%-linux-amd64 %BIN_NAME%-linux-arm64 %BIN_NAME%.exe %REMOTE_DEST%

if %ERRORLEVEL% EQU 0 (
    echo Deployment successful!
) else (
    echo Deployment failed with error code %ERRORLEVEL%.
)

pause