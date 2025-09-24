package main

import (
	"fmt"
	"log"
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

// fetchWithRedirect 发起 GET 请求，自动跟随重定向（最多 maxRedirects 次）
func fetchWithRedirect(client *fasthttp.Client, startURL string, maxRedirects int, headers []string, timeout int) (string, *fasthttp.Response, error) {
	currentURL := startURL
	if v, ok := CACHE_302_REDIRECT_URL.Get(startURL); ok {
		currentURL = v.(string)
		log.Printf("使用缓存的302地址：%s", currentURL)
	}

	for i := 0; i < maxRedirects; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.Header.SetMethod("GET")
		for _, head := range headers {
			key_value := strings.Split(head, ":")
			if len(key_value) == 2 {
				req.Header.Set(key_value[0], strings.TrimSpace(key_value[1]))
			}
		}

		req.SetRequestURI(currentURL)

		err := client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
		fasthttp.ReleaseRequest(req)
		if err != nil {
			fasthttp.ReleaseResponse(resp)
			CACHE_302_REDIRECT_URL.Delete(startURL)
			log.Printf("请求失败，清楚缓存的302地址：%s", currentURL)
			return currentURL, nil, fmt.Errorf("request failed: %w", err)
		}

		statusCode := resp.StatusCode()
		if statusCode >= 300 && statusCode < 400 {
			location := string(resp.Header.Peek("Location"))
			if location == "" {
				fasthttp.ReleaseResponse(resp)
				return currentURL, nil, fmt.Errorf("redirect without Location header")
			}

			if strings.Contains(location, "/http://") {
				location = strings.ReplaceAll(location, "/http://", "/http%3A%2F%2F")
			}

			if strings.Contains(location, "/https://") {
				location = strings.ReplaceAll(location, "/https://", "/https%3A%2F%2F")
			}

			u, err := url.Parse(location)
			if err != nil {
				fasthttp.ReleaseResponse(resp)
				return currentURL, nil, fmt.Errorf("invalid redirect URL: %v", err)
			}
			if !u.IsAbs() {
				base, _ := url.Parse(currentURL)
				location = base.ResolveReference(u).String()
			}
			currentURL = location
			fasthttp.ReleaseResponse(resp)
			continue
		}
		if startURL != currentURL && isSameFileName(startURL, currentURL) {
			CACHE_302_REDIRECT_URL.Add(startURL, currentURL, 1*time.Hour)
		}
		// 不是 3xx，直接返回
		return currentURL, resp, nil
	}

	return currentURL, nil, fmt.Errorf("too many redirects")
}

func HttpGetWithUA(client *fasthttp.Client, url string, headers []string, timeout int) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(url)
	for _, head := range headers {
		key_value := strings.Split(head, ":")
		if len(key_value) == 2 {
			req.Header.Set(key_value[0], strings.TrimSpace(key_value[1]))
		}
	}

	if err := client.DoTimeout(req, resp, time.Duration(timeout)*time.Second); err != nil {
		fasthttp.ReleaseRequest(req)
		fasthttp.ReleaseResponse(resp)
		return nil, err
	}

	fasthttp.ReleaseRequest(req) // 只释放请求，响应交给调用方
	return resp, nil
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
