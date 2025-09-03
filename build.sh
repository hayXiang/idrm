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
