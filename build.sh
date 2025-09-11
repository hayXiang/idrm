#!/bin/bash
BIN_NAME=idrm
#android
GOOS=android
GOARCH=arm64
CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${BIN_NAME}-${GOOS}-${GOARCH}

#linux
GOOS=linux
GOARCH=arm64
CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${BIN_NAME}-${GOOS}-${GOARCH}
GOARCH=amd64
CGO_ENABLED=0 GOOS=${GOOS} GOARCH=${GOARCH} go build -o ${BIN_NAME}-${GOOS}-${GOARCH}

#windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o ${BIN_NAME}.exe
chmod a+x idrm*
scp -P60112 idrm-android-arm64 idrm-linux-amd64 idrm-linux-arm64 idrm.exe root@public.hxiang.eu.org:/mnt/data/local-disk1/public/idrm/
