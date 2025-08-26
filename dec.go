package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

// AES-CENC解密
func decryptCENC(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, iv)
	decrypted := make([]byte, len(data))
	stream.XORKeyStream(decrypted, data)
	return decrypted, nil
}

// 补齐 IV 到 16 字节（前补0）
func padIV(iv8 []byte) []byte {
	iv := make([]byte, 16)
	copy(iv[8:], iv8)
	return iv
}

func decryptWidevine(inPath, outPath string, key []byte) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inFile.Close()

	mp4File, err := mp4.DecodeFile(inFile)
	if err != nil {
		return fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	var senc *mp4.SencBox
	// 查找 senc box并获取IV
	for _, trak := range mp4File.LastSegment().LastFragment().Moof.Trafs {
		var newBoxes []mp4.Box
		for _, box := range trak.Children {
			if box.Type() == "senc" {
				senc, _ = box.(*mp4.SencBox)
			} else {
				newBoxes = append(newBoxes, box)
			}
		}
		trak.Children = newBoxes
	}

	if senc == nil {
		return fmt.Errorf("未找到 senc box 或 IV")
	}

	// 解密 mdat
	var mdata = mp4File.LastSegment().LastFragment().Mdat
	if mdata != nil {
		encrypted := mdata.Data
		decrypted := make([]byte, 0, len(encrypted))
		offset := 0
		for i, sample := range senc.SubSamples {
			iv := padIV(senc.IVs[i])
			for _, sub := range sample {
				clearLen := int(sub.BytesOfClearData)
				cipherLen := int(sub.BytesOfProtectedData)
				// 先拼接明文
				if clearLen > 0 {
					decrypted = append(decrypted, encrypted[offset:offset+clearLen]...)
					offset += clearLen
				}
				// 再拼接解密后的密文
				if cipherLen > 0 {
					part, err := decryptCENC(encrypted[offset:offset+cipherLen], key, iv)
					if err != nil {
						return fmt.Errorf("解密失败: %w", err)
					}
					decrypted = append(decrypted, part...)
					offset += cipherLen
				}
			}
		}
		mdata.Data = decrypted
	}

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

func main() {
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

	err = decryptWidevine(inPath, outPath, key)
	if err != nil {
		fmt.Println("处理失败:", err)
	} else {
		fmt.Println("处理完成")
	}
}
