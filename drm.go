package main

import (
	"encoding/hex"
	"encoding/json"
	"idrm/decrypt"
	"fmt"
	"log"
	"net/http"
	"strings"
	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/valyala/fasthttp"
)


func fetchAndDecrypt(client *http.Client, config *StreamConfig, tvgID string, body []byte, ctx *fasthttp.RequestCtx, sinfBox *mp4.SinfBox, proxy_type string) ([]byte, error) {
	clientIP := ""
	if ctx != nil {
		clientIP = getClientIP(ctx)
	}
	log.Printf("[解密开始] tvgID=%s, type=%s, size=%d, client=%s", tvgID, proxy_type, len(body), clientIP)
	
	val, ok := clearKeysMap.Load(tvgID)
	if !ok {
		log.Printf("[解密错误] tvgID=%s, client=%s: 密钥未找到", tvgID, clientIP)
		err := fmt.Errorf("key not found for tvgID %s", tvgID)
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥不存在")
		}
		return nil, err
	}
	log.Printf("[解密进度] tvgID=%s: 已获取密钥信息", tvgID)

	// 如果已经有人在拉 license，可以直接返回，不等待
	// 可用一个 requestManager 或 map 来标记是否在获取
	if strings.HasPrefix(val.(string), "http") {
		log.Printf("[解密进度] tvgID=%s: 正在从 license URL 获取密钥: %s", tvgID, val.(string))
		_, licenseBody, err, _, _ := HttpGet(client, val.(string), config.LicenseUrlHeaders)
		if err != nil {
			log.Printf("[解密错误] tvgID=%s, client=%s: 获取 license 失败: %v", tvgID, clientIP, err)
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
				ctx.SetBodyString("无法获取 license")
			}
			return nil, fmt.Errorf("failed to fetch license: %v", err)
		}
		log.Printf("[解密进度] tvgID=%s: 成功获取 license, size=%d", tvgID, len(licenseBody))
		clearKeysMap.Store(tvgID, string(licenseBody))
		val = string(licenseBody)
	}

	// 解析 JWK
	if strings.Contains(val.(string), "kty") && strings.Contains(val.(string), "keys") {
		log.Printf("[解密进度] tvgID=%s: 解析 JWK 格式密钥", tvgID)
		var jwk JWKSet
		if err := json.Unmarshal([]byte(val.(string)), &jwk); err != nil {
			log.Printf("[解密错误] tvgID=%s: 解析 JWK 失败: %v", tvgID, err)
			return nil, err
		}
		for _, key := range jwk.Keys {
			kid, _ := base64DecodeWithPad(key.Kid)
			k, _ := base64DecodeWithPad(key.K)
			val = hex.EncodeToString(kid) + ":" + hex.EncodeToString(k)
		}
		log.Printf("[解密进度] tvgID=%s: JWK 解析完成", tvgID)
	}

	kidKey := strings.Split(val.(string), ":")
	if len(kidKey) != 2 {
		log.Printf("[解密错误] tvgID=%s: 密钥格式错误, val=%s", tvgID, val.(string))
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥格式错误," + val.(string))
		}
		return nil, fmt.Errorf("invalid key format: %s", val)
	}
	log.Printf("[解密进度] tvgID=%s: 密钥格式正确, kid=%s", tvgID, kidKey[0])

	keyBytes, err := hex.DecodeString(kidKey[1])
	if err != nil {
		log.Printf("[解密错误] tvgID=%s: 密钥解码失败: %v", tvgID, err)
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("密钥格式错误")
		}
		return nil, err
	}
	log.Printf("[解密进度] tvgID=%s: 密钥解码成功, keyLength=%d", tvgID, len(keyBytes))

	decryptedBody, err := decrypt.DecryptFromBody(proxy_type, body, keyBytes, sinfBox)
	if err != nil {
		log.Printf("[解密错误] tvgID=%s, client=%s: 解密失败: %v", tvgID, clientIP, err)
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("DRM 解密信息失败")
		}
		return nil, err
	}
	log.Printf("[解密完成] tvgID=%s, client=%s: 解密成功, inputSize=%d, outputSize=%d", tvgID, clientIP, len(body), len(decryptedBody))
	return decryptedBody, nil
}