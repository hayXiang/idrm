package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

// 补齐 IV 到 16 字节（前补0）
func padIV(iv8 []byte) []byte {
	iv := make([]byte, 16)
	copy(iv, iv8)
	return iv
}

func decryptWidevine(mp4File *mp4.File, key []byte) error {
	var senc *mp4.SencBox
	// 查找 senc box并获取IV
	trak := mp4File.LastSegment().LastFragment().Moof.Traf
	var newBoxes []mp4.Box
	for _, box := range trak.Children {
		if box.Type() == "senc" {
			senc, _ = box.(*mp4.SencBox)
		} else if (box.Type() != "saio") && (box.Type() != "saiz") {
			newBoxes = append(newBoxes, box)
		}
	}
	trak.Children = newBoxes

	if senc == nil {
		return fmt.Errorf("未找到 senc box 或 IV")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	// 解密 mdat
	var mdata = mp4File.LastSegment().LastFragment().Mdat
	if mdata != nil {
		encrypted := mdata.Data
		var decrypted []byte
		var offset uint32 = 0
		for i := 0; i < len(senc.IVs); i++ {
			iv := padIV(senc.IVs[i])
			stream := cipher.NewCTR(block, iv)

			if senc.SubSamples == nil {
				sampleSize := trak.Trun.Samples[i].Size
				part := make([]byte, sampleSize)
				stream.XORKeyStream(part, encrypted[offset:offset+sampleSize])
				decrypted = append(decrypted, part...)
				offset += sampleSize
			} else {
				sample := senc.SubSamples[i]
				for _, sub := range sample {
					clearLen := (uint32)(sub.BytesOfClearData)
					cipherLen := (uint32)(sub.BytesOfProtectedData)

					if clearLen > 0 {
						decrypted = append(decrypted, encrypted[offset:offset+clearLen]...)
						offset += clearLen
					}

					if cipherLen > 0 {
						part := make([]byte, cipherLen)
						stream.XORKeyStream(part, encrypted[offset:offset+cipherLen])
						decrypted = append(decrypted, part...)
						offset += cipherLen
					}
				}
			}
		}
		mdata.Data = decrypted
	}
	return nil
}

func decryptWidevineFromBody(data []byte, key []byte) ([]byte, error) {
	mp4File, err := mp4.DecodeFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("解析 MP4 文件失败: %w", err)
	}
	decryptWidevine(mp4File, key)
	return encodeMP4ToBytes(mp4File)
}

func decryptWidevineFromFile(inPath, outPath string, key []byte) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inFile.Close()

	mp4File, err := mp4.DecodeFile(inFile)
	if err != nil {
		return fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	decryptWidevine(mp4File, key)
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outFile.Close()

	err = mp4File.Encode(outFile)
	if err != nil {
		return fmt.Errorf("写入 MP4 文件失败: %w", err)
	}
	return nil
}

func zmain() {
	if len(os.Args) != 4 {
		fmt.Println("用法: dec <输入文件> <输出文件> <密钥(hex)>")
		return
	}
	inPath := os.Args[1]
	outPath := os.Args[2]
	keyHex := os.Args[3]

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		fmt.Println("密钥格式错误:", err)
		return
	}

	err = decryptWidevineFromFile(inPath, outPath, key)
	if err != nil {
		fmt.Println("处理失败:", err)
	} else {
		fmt.Println("处理完成")
	}
}
