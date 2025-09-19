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

func getIV(senc *mp4.SencBox, sinf *mp4.SinfBox, i int, iv16 *[16]byte) []byte {
	if senc != nil && len(senc.IVs) > 0 {
		return padIV(senc.IVs[i], iv16)
	}

	if sinf != nil && sinf.Schi != nil && sinf.Schi.Tenc != nil {
		return padIV(sinf.Schi.Tenc.DefaultConstantIV, iv16)
	}
	return iv16[:]
}

func fetchAndDecrypt(client *fasthttp.Client, config *StreamConfig, tvgID string, body []byte, ctx *fasthttp.RequestCtx, sinfBox *mp4.SinfBox, proxy_type string) ([]byte, error) {
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

	body, err = decryptFromBody(proxy_type, body, keyBytes, sinfBox)
	if err != nil {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("DRM 解密信息失败")
		}
		return nil, err
	}
	return body, nil
}

func decryptFromBody(proxy_type string, data []byte, key []byte, sinfBox *mp4.SinfBox) ([]byte, error) {
	if proxy_type == "ts" {
		decryptTS(data, key, sinfBox.Schi.Tenc.DefaultConstantIV)
		return data, nil
	} else {
		mp4File, err := mp4.DecodeFile(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("解析 MP4 文件失败: %w", err)
		}
		decrypFromMp4("widevine", mp4File, key, sinfBox)
		return encodeMP4ToBytes(mp4File)
	}
}

type DecryptCallback func(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32) error

func decrypt(sinfBox *mp4.SinfBox, mp4File *mp4.File, key []byte, doDecryptFuc DecryptCallback) error {
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

	if sinfBox == nil && senc == nil {
		//没有sinfBox,同时m4f也没有加密信息，判断为不用解密
		return nil
	}

	mdata := frag.Mdat
	if mdata == nil {
		return fmt.Errorf("未找到 mdat")
	}

	// AES block 只创建一次
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	sampleCount := len(traf.Trun.Samples)
	var wg sync.WaitGroup
	offsets := make([]uint32, sampleCount)
	curr := uint32(0)
	if sampleCount > 0 {
		for i := 0; i < int(sampleCount); i++ {
			offsets[i] = curr
			curr += traf.Trun.Samples[i].Size
		}
	}
	for i := 0; i < int(sampleCount); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			doDecryptFuc(block, mdata, senc, traf, i, offsets[i])
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

func decrypFromMp4(drmType string, mp4File *mp4.File, key []byte, sinfBox *mp4.SinfBox) error {
	return decrypt(sinfBox, mp4File, key, func(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32) error {
		//自动检测加密类型
		if sinfBox != nil && sinfBox.Schm != nil {
			if sinfBox.Schm.SchemeType == "cbcs" {
				drmType = "fairplay"
			} else {
				drmType = "widevine"
			}
		}

		if drmType == "widevine" {
			DecryptWidevineSample(block, mdat, senc, traf, i, offset, sinfBox)
		} else {
			DecryptFairplaySample(block, mdat, senc, traf, i, offset, sinfBox)
		}
		return nil
	})
}

// 从文件解密并写入输出
func decryptFromFile(inPath, outPath string, key []byte, drmType string) error {
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inFile.Close()

	mp4File, err := mp4.DecodeFile(inFile)
	if err != nil {
		return fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	if err = decrypFromMp4(drmType, mp4File, key, nil); err != nil {
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
