package main

import (
	"errors"
	"fmt"
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
	const maxRetries = 3
	var lastErr error
	var contentLength int64
	
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("[HttpGet重试] URL=%s, 第%d次重试", startURL, attempt)
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond) // 递增延迟
		}
		
		statusCode, body, contentLength, err, contentType, url_302 = httpGetOnce(client, startURL, headers)
		if err != nil {
			lastErr = err
			continue // 出错则重试
		}
		
		// 检查内容大小是否与 Content-Length 一致
		// 如果 Content-Length = 0 但 body 不为空，直接返回（可能是 chunked 传输）
		if contentLength == 0 && len(body) > 0 {
			log.Printf("[HttpGet] URL=%s, Content-Length=0, 实际大小=%d, 直接返回", startURL, len(body))
			return statusCode, body, nil, contentType, url_302
		}
		if contentLength > 0 && int64(len(body)) != contentLength {
			log.Printf("[HttpGet大小不一致] URL=%s, Content-Length=%d, 实际大小=%d", startURL, contentLength, len(body))
			lastErr = fmt.Errorf("内容大小不一致: 期望%d, 实际%d", contentLength, len(body))
			continue // 大小不一致则重试
		}
		
		// 成功返回
		if attempt > 0 {
			log.Printf("[HttpGet重试成功] URL=%s, 第%d次重试成功", startURL, attempt)
		}
		return statusCode, body, nil, contentType, url_302
	}
	
	// 所有重试都失败
	log.Printf("[HttpGet失败] URL=%s, 重试%d次后仍然失败: %v", startURL, maxRetries, lastErr)
	return statusCode, body, lastErr, contentType, url_302
}

// httpGetOnce 执行单次 HTTP GET 请求，返回内容长度用于校验
func httpGetOnce(client *http.Client, startURL string, headers []string) (statusCode int, body []byte, contentLength int64, err error, contentType string, url_302 string) {
	currentURL := startURL
	is_cached_302_url := false
	if v, ok := CACHE_302_REDIRECT_URL.Get(startURL); ok {
		is_cached_302_url = true
		currentURL = v.(string)
		log.Printf("使用缓存的302地址：%s", currentURL)
	}
	req, err := http.NewRequest("GET", currentURL, nil)
	if err != nil {
		return 503, nil, 0, err, "", startURL
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
		return 503, nil, 0, err, "", startURL
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		CACHE_302_REDIRECT_URL.Delete(startURL)
		return resp.StatusCode, nil, 0, errors.New("http get failed," + resp.Status), "", startURL
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
	return resp.StatusCode, _body, resp.ContentLength, nil, contentType, currentURL
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
