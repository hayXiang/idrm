package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var m3uURL string
var port string

var client = &fasthttp.Client{
	ReadTimeout:     30 * time.Second, // 读取响应超时
	WriteTimeout:    10 * time.Second, // 写请求超时
	MaxConnsPerHost: 500,              // 限制连接数
}

func main() {
	flag.StringVar(&m3uURL, "i", "", "输入 M3U URL")
	flag.StringVar(&port, "p", ":1234", "代理服务器端口，默认 :1234")
	flag.Parse()

	if m3uURL == "" {
		log.Fatal("请使用 -i 参数输入 M3U URL")
	}

	var enablePprof bool
	var pprofAddr string

	flag.BoolVar(&enablePprof, "pprof-enable", false, "Enable pprof HTTP server")
	flag.StringVar(&pprofAddr, "pprof-addr", "localhost:7070", "pprof listen address")

	if enablePprof {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Fatalf("pprof server error: %v", err)
			}
		}()
	}

	fmt.Println("代理服务器启动在 :" + port)
	if err := fasthttp.ListenAndServe(port, requestHandler); err != nil {
		log.Fatalf("ListenAndServe error: %s", err)
	}
}

func HttpGetWithUA(url string) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(url)
	req.Header.Set("User-Agent", "okhttp/4.12.0")

	if err := client.Do(req, resp); err != nil {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	fasthttp.ReleaseRequest(req) // 只释放请求，响应交给调用方
	return resp, nil
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

var reTvg = regexp.MustCompile(`tvg-id="([^"]+)"`)
var reDrm = regexp.MustCompile(`drm_legacy=org\.w3\.clearkey\|([0-9a-fA-F]+):([0-9a-fA-F]+)`)

func proxyM3U(ctx *fasthttp.RequestCtx) {
	resp, err := HttpGetWithUA(m3uURL)
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取 M3U")
		return
	}
	defer fasthttp.ReleaseResponse(resp)

	lines := strings.Split(string(resp.Body()), "\n")
	base, _ := url.Parse(m3uURL)

	var tvgID, kid, key string
	var newLines []string
	newLines = append(newLines, "#EXTM3U")

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
				strings.Replace(u.String(), "://", "/", 1))
			newLines = append(newLines, proxyPath)
		}
	}

	ctx.SetContentType("text/plain")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBodyString(strings.Join(newLines, "\n"))
}

var re = regexp.MustCompile(`URI="([^"]+)"`)

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
	proxy_url := strings.Replace(parts[4], "http/", "http://", 1)
	proxy_url = strings.Replace(proxy_url, "https/", "https://", 1)
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
	resp, err := HttpGetWithUA(proxy_url)
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取内容U")
		return
	}
	defer fasthttp.ReleaseResponse(resp)
	body := resp.Body()
	contentType := string(resp.Header.ContentType())
	if proxy_type == "m3u8" {
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
