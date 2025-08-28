package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strings"

	"github.com/valyala/fasthttp"
)

var m3uURL string
var port string

func main() {
	flag.StringVar(&m3uURL, "i", "", "输入 M3U URL")
	flag.StringVar(&port, "p", ":1234", "代理服务器端口，默认 :1234")
	flag.Parse()

	if m3uURL == "" {
		log.Fatal("请使用 -i 参数输入 M3U URL")
	}

	fmt.Println("代理服务器启动在 :" + port)
	if err := fasthttp.ListenAndServe(port, requestHandler); err != nil {
		log.Fatalf("ListenAndServe error: %s", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	switch {
	case strings.HasPrefix(path, "/drm/proxy/"):
		proxyStreamURL(ctx, path)
	case strings.HasSuffix(path, "index.m3u8"):
		proxyM3U(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString("Not Found")
	}
}

func proxyM3U(ctx *fasthttp.RequestCtx) {
	status, body, err := fasthttp.Get(nil, m3uURL)
	if err != nil || status != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取 M3U")
		return
	}

	lines := strings.Split(string(body), "\n")
	base, _ := url.Parse(m3uURL)

	var tvgID, kid, key string
	var newLines []string
	newLines = append(newLines, "#EXTM3U")

	reTvg := regexp.MustCompile(`tvg-id="([^"]+)"`)
	reDrm := regexp.MustCompile(`drm_legacy=org\.w3\.clearkey\|([0-9a-fA-F]+):([0-9a-fA-F]+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#EXTM3U") {
			continue
		}

		// 解析 EXTINF 行
		if strings.HasPrefix(line, "#EXTINF") {
			matches := reTvg.FindStringSubmatch(line)
			if len(matches) == 2 {
				tvgID = matches[1]
			} else {
				tvgID = "unknown"
			}

			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 2 {
				newLines = append(newLines, "#EXTINF:-1,"+parts[1])
			} else {
				newLines = append(newLines, "#EXTINF:-1,Stream")
			}
			continue
		}

		// 解析 Kodi DRM 标签
		if strings.HasPrefix(line, "#KODIPROP:") {
			matches := reDrm.FindStringSubmatch(line)
			if len(matches) == 3 {
				kid = matches[1]
				key = matches[2]
			}
			continue
		}

		// 普通流 URL
		u, err := base.Parse(line)
		if err == nil {
			proxyPath := fmt.Sprintf("/drm/proxy/m3u8/%s/%s/%s/%s",
				tvgID,
				kid,
				key,
				strings.ReplaceAll(u.String(), "://", "/"))
			newLines = append(newLines, proxyPath)
		}
	}

	ctx.SetContentType("text/plain")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(strings.Join(newLines, "\n"))
}

// 代理流 URL
func proxyStreamURL(ctx *fasthttp.RequestCtx, path string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/drm/proxy/"), "/", 5)
	if len(parts) < 5 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Invalid proxy URL")
		return
	}
	proxy_type := parts[0]
	tvgID := parts[1]
	kid := parts[2]
	key := parts[3]
	proxy_url := strings.ReplaceAll(parts[4], "http/", "http://")
	proxy_url = strings.ReplaceAll(proxy_url, "https/", "https://")
	query := string(ctx.QueryArgs().QueryString())
	if query != "" {
		proxy_url += "?" + query
	}

	key_bytes, err := hex.DecodeString(key)
	if err != nil {
		fmt.Println("密钥格式错误:", err)
		return
	}

	// 直接重定向到原始 URL
	status, body, err := fasthttp.Get(nil, proxy_url)
	if err != nil || status != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取 M3U")
		return
	}

	// 使用 fasthttp.Client 获取远程响应头和 body
	client := &fasthttp.Client{}
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(proxy_url)
	if err := client.Do(req, resp); err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取内容")
		return
	}

	body = resp.Body()
	contentType := string(resp.Header.ContentType())
	re := regexp.MustCompile(`URI="([^"]+)"`)
	if proxy_type == "m3u8" {
		//if strings.HasPrefix(contentType, "text/plain") || strings.Contains(strings.ToLower(contentType), "mpegurl") {
		lines := strings.Split(string(body), "\n")
		var newLines []string
		var lastLineWasExtInf bool
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "#EXT-X-KEY") {
				continue
			}

			if strings.HasPrefix(line, "#EXT-X-MAP:URI=") {
				matches := re.FindStringSubmatch(line)
				if len(matches) == 2 {
					originalURI := matches[1]
					var finalURI string
					if strings.HasPrefix(originalURI, "/") {
						u, err := url.Parse(proxy_url)
						if err == nil {
							base := u.Scheme + "://" + u.Host
							finalURI = base + originalURI
							finalURI = fmt.Sprintf("/drm/proxy/init-m4s/%s/%s/%s/%s", tvgID, kid, key, strings.Replace(finalURI, "://", "/", 1))
							line = re.ReplaceAllString(line, `URI="`+finalURI+`"`)
						}
					}
				}
			}

			// 标记上一行是 #EXTINF
			if strings.HasPrefix(line, "#EXTINF") {
				lastLineWasExtInf = true
				newLines = append(newLines, line)
				continue
			}

			// 如果上一行是 #EXTINF，当前行是分片地址，需要代理
			if lastLineWasExtInf && line != "" && strings.HasPrefix(line, "/") {
				var finalURI string
				u, err := url.Parse(proxy_url)
				if err == nil {
					base := u.Scheme + "://" + u.Host
					finalURI = base + line
					finalURI = fmt.Sprintf("/drm/proxy/m4s/%s/%s/%s/%s", tvgID, kid, key, strings.Replace(finalURI, "://", "/", 1))
					line = finalURI
				}
				lastLineWasExtInf = false
			}
			newLines = append(newLines, line)
		}
		body = []byte(strings.Join(newLines, "\n"))
		ctx.SetContentType("text/plain")
	} else if proxy_type == "init-m4s" {
		body, err = removePsshAndSinfFromBody(body)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("移除 DRM 信息失败")
			return
		}
		ctx.SetContentType(contentType)
	} else if proxy_type == "m4s" {
		body, err = decryptWidevineFromBody(body, key_bytes)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("DRM 解密信息失败")
			return
		}
		ctx.SetContentType(contentType)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(body)
}
