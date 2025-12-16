package main

import (
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

func getClientIP(ctx *fasthttp.RequestCtx) string {
	xForwardedFor := ctx.Request.Header.Peek("X-Forwarded-For")
	if len(xForwardedFor) > 0 {
		// 可能是多个 IP，用逗号分隔
		ips := strings.Split(string(xForwardedFor), ",")
		return strings.TrimSpace(ips[0])
	}
	return ctx.RemoteAddr().String()
}

func isSameFileName(url1, url2 string) bool {
	u1, err1 := url.Parse(url1)
	u2, err2 := url.Parse(url2)
	if err1 != nil || err2 != nil {
		return false
	}

	// 获取 URL 的最后一个路径段（文件名）
	file1 := path.Base(u1.Path)
	file2 := path.Base(u2.Path)

	return file1 == file2
}

func HttpGet(client *http.Client, startURL string, headers []string) (statusCode int, body []byte, err error, contentType string, url_302 string) {
	currentURL := startURL
	is_cached_302_url := false
	if v, ok := CACHE_302_REDIRECT_URL.Get(startURL); ok {
		is_cached_302_url = true
		currentURL = v.(string)
		log.Printf("使用缓存的302地址：%s", currentURL)
	}
	req, err := http.NewRequest("GET", currentURL, nil)
	if err != nil {
		return 503, nil, err, "", startURL
	}

	for _, head := range headers {
		kv := strings.SplitN(head, ":", 2)
		if len(kv) == 2 {
			req.Header.Set(strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		CACHE_302_REDIRECT_URL.Delete(startURL)
		return 503, nil, err, "", startURL
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		CACHE_302_REDIRECT_URL.Delete(startURL)
		return resp.StatusCode, nil, errors.New("http get failed," + resp.Status), "", startURL
	}
	currentURL = resp.Request.URL.String()
	if !is_cached_302_url && startURL != currentURL && !strings.Contains(currentURL, "https://live.9528.eu.org/error/") {
		if isSameFileName(startURL, currentURL) {
			CACHE_302_REDIRECT_URL.Add(startURL, currentURL, 1*time.Hour)
		} else {
			CACHE_302_REDIRECT_URL.Add(startURL, currentURL, 1*time.Minute)
		}
	}
	_body, _ := io.ReadAll(resp.Body)
	contentType = resp.Header.Get("Content-Type")
	return resp.StatusCode, _body, err, contentType, currentURL
}

func GetForwardHeader(ctx *fasthttp.RequestCtx, header, fallback string) string {
	if ctx == nil {
		return ""
	}
	if val := ctx.Request.Header.Peek(header); val != nil {
		return string(val)
	}
	return fallback
}

func getAliasFromPath(path string) string {
	// 去掉查询参数
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	// 获取最后一个 /
	idx := strings.LastIndex(path, "/")
	name := path
	if idx != -1 {
		name = path[idx+1:]
	}
	// 去掉 .m3u8 后缀
	name = strings.TrimSuffix(name, ".m3u")
	name = strings.TrimSuffix(name, ".m3u8")
	return name
}

func resolveURL(targetUrl string, baseUrl string) string {
	var finalURI string
	if strings.HasPrefix(targetUrl, "/") {
		u, err := url.Parse(baseUrl)
		if err == nil {
			base := u.Scheme + "://" + u.Host
			finalURI = base + targetUrl
		}
	} else if strings.HasPrefix(targetUrl, "http") {
		finalURI = targetUrl
	} else {
		idx := strings.LastIndex(baseUrl, "/")
		finalURI = baseUrl[:idx] + "/" + targetUrl
	}
	return finalURI
}
