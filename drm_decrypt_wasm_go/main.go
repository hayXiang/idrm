//go:wasm-module
// +build js,wasm

package main

import (
	"encoding/hex"
	"syscall/js"
	"strings"
	// 引入项目原有的解密功能
	"github.com/Eyevinn/mp4ff/mp4"
	// 引入公共函数库
	"idrm/decrypt"
)

// 全局键存储
var keys = make(map[string][]byte)

// 全局sinfBox存储，按streamId索引
var sinfBoxMap = make(map[string]*mp4.SinfBox)

// 添加键
func addKey(this js.Value, args []js.Value) interface{} {
	kid := args[0].String()
	keyHex := args[1].String()
	
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		println("Error decoding key:", err.Error())
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	}
	
	keys[kid] = key
	
	// 添加调试日志
	println("Added key for KID:", kid)
	
	return js.ValueOf(map[string]interface{}{
		"success": true,
		"message": "Key added successfully",
	})
}

// 解密fMP4段
func decryptSegment(this js.Value, args []js.Value) interface{} {
	data := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(data, args[0])
	
	kid := args[1].String()
	uuid := args[2].String()
	
	key, exists := keys[kid]
	if !exists {
		println("Key not found for KID:", kid)
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "Key not found for KID: " + kid,
		})
	}
	
	println("Found key for KID:", kid, ", key length:", len(key))

	// 从map中获取对应的sinfBox
	sinfBox, exists := sinfBoxMap[uuid]
	if !exists {
		println("SinfBox not found for UUID:", uuid)
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "SinfBox not found for UUID: " + uuid,
		})
	}
	
	drmType := "m4s"
	// Fixed: Using SchemeVersion instead of SchemaVersion
	if sinfBox != nil && sinfBox.Schm != nil && sinfBox.Schm.SchemeType == "cbcs" && sinfBox.Schm.SchemeVersion == 9527 {
		drmType = "ts"
	}
	result, err := decrypt.DecryptFromBody(drmType, data, key, sinfBox)
	if err != nil {
		println("Failed to decrypt MP4 file:", err.Error())
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "Failed to decrypt MP4 file: " + err.Error(),
		})
	}

	// 创建Uint8Array并复制结果
	uint8Array := js.Global().Get("Uint8Array").New(len(result))
	js.CopyBytesToJS(uint8Array, result)
	
	println("Successfully decrypted segment, size:", len(data), "->", len(result))
	
	return js.ValueOf(map[string]interface{}{
		"success": true,
		"data":    uint8Array,
	})
}


// 修改初始化M4S片段 - 直接使用decrypt包中的函数，增加调试日志
func initCbcsTsContext(this js.Value, args []js.Value) interface{}  {
	kid := args[0].String()
	iv := args[1].String()
	uuid := args[2].String() // Fixed: was using args[2] twice

	println("initCbcsTsContext for KID:", kid)
	_, exists := sinfBoxMap[uuid] // Fixed: was using .Load() on regular map
	if !exists {
		sinBox := new(mp4.SinfBox)
		sinBox.Schm = new(mp4.SchmBox)
		sinBox.Schi = new(mp4.SchiBox)
		sinBox.Schi.Tenc = new(mp4.TencBox)

		sinBox.Schm.SchemeType = "cbcs"
		sinBox.Schm.SchemeVersion = 9527
		// Fixed: converting string to []byte
		// 3. 转换为字节数组
		ivBytes, err := hex.DecodeString(strings.TrimPrefix(iv, "0x"))
		if err != nil {
			return js.ValueOf(map[string]interface{}{
				"success": false,
				"error":   "Failed to decode IV: " + err.Error(),
			})
		}
		sinBox.Schi.Tenc.DefaultConstantIV = ivBytes
		sinfBoxMap[uuid] = sinBox
		println("Stored sinfBox for uuid:", uuid)
	}
	return js.ValueOf(map[string]interface{}{
			"success": true,
	})
}

// 修改初始化M4S片段 - 直接使用decrypt包中的函数，增加调试日志
func modifyInitM4s(this js.Value, args []js.Value) interface{} {
	initData := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(initData, args[0])
	
	kid := args[1].String()
	uuid := args[2].String()

	println("Processing init segment for KID:", kid)
	println("Init segment size:", len(initData))

	// 调用decrypt包中的ModifyInitM4sFromBody函数
	body, sinfBox, err := decrypt.ModifyInitM4sFromBody(initData)
	
	if err != nil {
		println("Error in ModifyInitM4sFromBody:", err.Error())
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "Failed to process init segment: " + err.Error(),
		})
	}
	
	println("Successfully processed init segment, size:", len(initData), "->", len(body))
	
	// 检查大小是否真的改变了
	if len(body) == len(initData) {
		println("Warning: init segment size did not change after processing, may mean no boxes were removed")
	} else if len(body) < len(initData) {
		println("Info: init segment was reduced by", len(initData)-len(body), "bytes")
	} else {
		println("Info: init segment increased by", len(body)-len(initData), "bytes")
	}
	
	// 将sinfBox存储到全局map中
	if uuid != "" && sinfBox != nil {
		sinfBoxMap[uuid] = sinfBox
		println("Stored sinfBox for uuid:", uuid)
	} else if uuid == "" {
		println("Warning: UUID is empty")
		return js.ValueOf(map[string]interface{}{
			"success": false,
			"error":   "UUID is empty",
		})
	} else {
		println("Info: sinfBox is nil (this may be normal if no sinf box was present)")
	}

	// 返回成功结果
	uint8Array := js.Global().Get("Uint8Array").New(len(body))
	js.CopyBytesToJS(uint8Array, body)

	return js.ValueOf(map[string]interface{}{
		"success": true,
		"data":    uint8Array, // 返回处理后的body数据
	})
}

func main() {
	// 注册JavaScript回调函数
	js.Global().Set("addKey", js.FuncOf(addKey))
	js.Global().Set("modifyInitM4s", js.FuncOf(modifyInitM4s))
	js.Global().Set("initCbcsTsContext", js.FuncOf(initCbcsTsContext))
	js.Global().Set("decryptSegment", js.FuncOf(decryptSegment))

	// 创建一个永不关闭的channel，防止Go程序退出
	done := make(chan bool, 0)
	<-done
}