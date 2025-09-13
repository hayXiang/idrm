package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/valyala/fasthttp"
)

// 前补零 IV 到 16 字节，使用复用数组避免重复分配
func padIV(iv8 []byte, iv16 *[16]byte) []byte {
	for i := range iv16 {
		iv16[i] = 0
	}
	copy(iv16[:], iv8)
	return iv16[:]
}

func decryptWidevine(mp4File *mp4.File, key []byte) error {

	var traf *mp4.TrafBox = nil
	var frag *mp4.Fragment = nil

	//找到fragment
	for i := len(mp4File.Segments) - 1; i >= 0; i-- {
		seg := mp4File.Segments[i]
		if len(seg.Fragments) > 0 {
			// 取最后一个 fragment
			frag = seg.Fragments[len(seg.Fragments)-1]
			if frag.Moof != nil && len(frag.Moof.Trafs) > 0 {
				traf = frag.Moof.Trafs[0]
				break
			}
		}
	}

	if traf == nil {
		return fmt.Errorf("未找到 traf")
	}

	// 查找 SENC box,并删除
	var senc *mp4.SencBox
	var newBoxes []mp4.Box
	for _, box := range traf.Children {
		if box.Type() == "senc" {
			senc, _ = box.(*mp4.SencBox)
		} else if box.Type() != "saio" && box.Type() != "saiz" && box.Type() != "sbgp" && box.Type() != "sgpd" {
			newBoxes = append(newBoxes, box)
		}
	}

	if traf.Trun != nil {
		flags, is_present := traf.Trun.FirstSampleFlags()
		if is_present {
			flags &^= 0x00010000
			traf.Trun.SetFirstSampleFlags(flags)
		}
	}
	traf.Children = newBoxes
	if senc == nil {
		return fmt.Errorf("未找到 senc box")
	}

	// AES block 只创建一次
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	mdata := frag.Mdat
	if mdata == nil {
		return fmt.Errorf("未找到 mdat")
	}

	encrypted := mdata.Data
	var wg sync.WaitGroup
	offsets := make([]uint32, len(senc.IVs))
	curr := uint32(0)
	for i := 0; i < len(senc.IVs); i++ {
		offsets[i] = curr
		if senc.SubSamples == nil {
			curr += traf.Trun.Samples[i].Size
		} else {
			for _, sub := range senc.SubSamples[i] {
				curr += uint32(sub.BytesOfClearData) + uint32(sub.BytesOfProtectedData)
			}
		}
	}
	for i := 0; i < len(senc.IVs); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			offset := offsets[i]
			// 创建 CTR stream
			var iv16 [16]byte
			iv := padIV(senc.IVs[i], &iv16)
			stream := cipher.NewCTR(block, iv)

			if senc.SubSamples == nil {
				size := traf.Trun.Samples[i].Size
				stream.XORKeyStream(encrypted[offset:offset+size], encrypted[offset:offset+size])
			} else {
				for _, sub := range senc.SubSamples[i] {
					offset += uint32(sub.BytesOfClearData)
					cipherLen := uint32(sub.BytesOfProtectedData)
					if cipherLen > 0 {
						stream.XORKeyStream(encrypted[offset:offset+cipherLen], encrypted[offset:offset+cipherLen])
						offset += cipherLen
					}
				}
			}
		}(i)
	}
	wg.Wait()
	{
		// 查找 pssh， 并删除
		var newBoxes []mp4.Box
		for _, box := range frag.Moof.Children {
			if box.Type() != "pssh" {
				newBoxes = append(newBoxes, box)
			}
		}
		frag.Moof.Children = newBoxes
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

// 从文件解密并写入输出
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

	if err := decryptWidevine(mp4File, key); err != nil {
		return err
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outFile.Close()

	if err := mp4File.Encode(outFile); err != nil {
		return fmt.Errorf("写入 MP4 文件失败: %w", err)
	}
	return nil
}

func fetchAndDecryptWidevineBody(client *fasthttp.Client, config *StreamConfig, tvgID, proxyURL string, body []byte, ctx *fasthttp.RequestCtx) ([]byte, error) {
	val, ok := clearKeysMap.Load(tvgID)
	if !ok {
		err := fmt.Errorf("key not found for tvgID %s", tvgID)
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥不存在")
		}
		return nil, err
	}

	// 如果已经有人在拉 license，可以直接返回，不等待
	// 可用一个 requestManager 或 map 来标记是否在获取
	if strings.HasPrefix(val.(string), "http") {
		resp, err := HttpGetWithUA(client, val.(string), config.LicenseUrlHeaders, *config.HttpTimeout)
		if err != nil || resp.StatusCode() != fasthttp.StatusOK {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
				ctx.SetBodyString("无法获取 license")
			}
			return nil, fmt.Errorf("failed to fetch license: %v", err)
		}
		val = string(resp.Body())
		clearKeysMap.Store(tvgID, val)
		fasthttp.ReleaseResponse(resp)
	}

	// 解析 JWK
	if strings.Contains(val.(string), "kty") && strings.Contains(val.(string), "keys") {
		var jwk JWKSet
		if err := json.Unmarshal([]byte(val.(string)), &jwk); err != nil {
			return nil, err
		}
		for _, key := range jwk.Keys {
			kid, _ := base64DecodeWithPad(key.Kid)
			k, _ := base64DecodeWithPad(key.K)
			val = hex.EncodeToString(kid) + ":" + hex.EncodeToString(k)
		}
	}

	kidKey := strings.Split(val.(string), ":")
	if len(kidKey) != 2 {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥格式错误," + val.(string))
		}
		return nil, fmt.Errorf("invalid key format: %s", val)
	}

	keyBytes, err := hex.DecodeString(kidKey[1])
	if err != nil {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥格式错误")
		}
		return nil, err
	}

	body, err = decryptWidevineFromBody(body, keyBytes)
	if err != nil {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("DRM 解密信息失败")
		}
		return nil, err
	}
	return body, nil
}

func xxxmain() {
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

	if err := decryptWidevineFromFile(inPath, outPath, key); err != nil {
		fmt.Println("解密失败:", err)
	} else {
		fmt.Println("解密完成")
	}
}
