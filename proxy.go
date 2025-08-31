package main

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

var inputs multiFlag

type multiFlag []string

func (m *multiFlag) String() string {
	return fmt.Sprintf("%v", *m)
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

var port string

func newFastHTTPClient(socks5_url string) *fasthttp.Client {
	client := &fasthttp.Client{
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    10 * time.Second,
		MaxConnsPerHost: 500,
	}

	if socks5_url != "" {
		dialer, err := proxy.SOCKS5("tcp", strings.TrimPrefix(socks5_url, "socks5://"), nil, proxy.Direct)
		if err != nil {
			log.Fatalf("无法创建 SOCKS5 代理: %v", err)
		}
		client.Dial = func(addr string) (net.Conn, error) {
			return dialer.Dial("tcp", addr)
		}
	}
	return client
}

type JWKSet struct {
	Keys []struct {
		Kty string `json:"kty"`
		K   string `json:"k"`
		Kid string `json:"kid"`
	} `json:"keys"`
	Type string `json:"type"`
}

func base64DecodeWithPad(s string) ([]byte, error) {
	padding := (4 - len(s)%4) % 4
	s += strings.Repeat("=", padding)
	return base64.StdEncoding.DecodeString(s)
}

var m3uURLs = make(map[string]string)
var m3uProxyUrls = make(map[string]string)
var clientsByAlias = make(map[string]*fasthttp.Client)
var clientsByTvgId = make(map[string]*fasthttp.Client)
var DEFAULT_CLIENT *fasthttp.Client

func main() {
	flag.Var(&inputs, "i", "M3U 别名=URL, 可以指定多个 -i")
	flag.StringVar(&port, "p", ":1234", "代理服务器端口，默认 :1234")
	flag.Parse()

	for index, in := range inputs {
		kv := strings.SplitN(in, "#", 3)
		alias := fmt.Sprintf("index-%d", index)
		if index == 0 {
			alias = "index"
		}
		if len(kv) == 3 {
			alias = strings.TrimSpace(kv[1])
			m3uURLs[alias] = strings.TrimSpace(kv[2])
			m3uProxyUrls[alias] = strings.TrimSpace(kv[0])
		} else if len(kv) == 2 {
			alias = strings.TrimSpace(kv[0])
			m3uURLs[alias] = strings.TrimSpace(kv[1])
			m3uProxyUrls[alias] = ""
		} else if len(kv) == 1 {
			m3uURLs[alias] = in
			m3uProxyUrls[alias] = ""
		}
	}
	for alias, socks5_url := range m3uProxyUrls {
		clientsByAlias[alias] = newFastHTTPClient(socks5_url)
	}
	DEFAULT_CLIENT = newFastHTTPClient("")

	var enablePprof bool
	var pprofAddr string

	flag.BoolVar(&enablePprof, "pprof-enable", false, "Enable pprof HTTP server")
	flag.StringVar(&pprofAddr, "pprof-addr", "localhost:7070", "pprof listen address")
	for alias, _ := range m3uURLs {
		go func() {
			proxyM3U(nil, alias)
		}()
	}

	if enablePprof {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Fatalf("pprof server error: %v", err)
			}
		}()
	}

	log.Println("代理服务器启动在 :" + port)
	if err := fasthttp.ListenAndServe(port, requestHandler); err != nil {
		log.Fatalf("ListenAndServe error: %s", err)
	}
}

// fetchWithRedirect 发起 GET 请求，自动跟随重定向（最多 maxRedirects 次）
func fetchWithRedirect(client *fasthttp.Client, startURL string, maxRedirects int, ua string) (string, *fasthttp.Response, error) {
	currentURL := startURL

	for i := 0; i < maxRedirects; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(currentURL)
		req.Header.SetMethod("GET")
		if ua == "" {
			req.Header.Set("User-Agent", "okhttp/4.12.0")
		} else {
			req.Header.Set("User-Agent", ua)
		}

		err := client.Do(req, resp)
		fasthttp.ReleaseRequest(req)
		if err != nil {
			fasthttp.ReleaseResponse(resp)
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

		// 不是 3xx，直接返回
		return currentURL, resp, nil
	}

	return currentURL, nil, fmt.Errorf("too many redirects")
}

func HttpGetWithUA(client *fasthttp.Client, url string, ua string) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(url)
	if ua == "" {
		req.Header.Set("User-Agent", "okhttp/4.12.0")
	} else {
		req.Header.Set("User-Agent", ua)
	}

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
	case strings.HasSuffix(path, ".m3u"):
		proxyM3U(ctx, "")
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString("Not Found")
	}
}

var reTvg = regexp.MustCompile(`tvg-id="([^"]+)"`)
var reDrm = regexp.MustCompile(`drm_legacy=org\.w3\.clearkey\|([0-9a-fA-F]+):([0-9a-fA-F]+)`)
var reValidTvg = regexp.MustCompile(`^[0-9a-zA-Z_-]+$`)
var clearKeysMap = make(map[string]string)

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

// 使用示例
func proxyM3U(ctx *fasthttp.RequestCtx, alias string) {
	if ctx != nil {
		alias = getAliasFromPath(string(ctx.URI().Path()))
	}
	m3uURL, ok := m3uURLs[alias] // ok 表示 alias 是否存在
	if !ok {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("不存在数据")
		}
		return
	}

	resp, err := HttpGetWithUA(DEFAULT_CLIENT, m3uURL, "")
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("无法获取 M3U")
		}
		return
	}
	defer fasthttp.ReleaseResponse(resp)

	lines := strings.Split(string(resp.Body()), "\n")
	base, _ := url.Parse(m3uURL)

	var tvgID, clearkey string
	var newLines []string
	newLines = append(newLines, "#EXTM3U")

	var _port string
	var _host string
	if ctx != nil {
		if h, p, err := net.SplitHostPort(string(ctx.Host())); err == nil {
			_port = p
			_host = h
		} else {
			// 没有指定端口，根据 scheme 推断
			if string(ctx.URI().Scheme()) == "https" {
				_port = "443"
			} else {
				_port = "80"
			}
		}
	}
	var schema = ""
	var port = ""
	var serverName = ""
	if ctx != nil {
		schema = GetForwardHeader(ctx, "X-Forwarded-Proto", string(ctx.URI().Scheme()))
		port = GetForwardHeader(ctx, "X-Forwarded-Port", _port)
		serverName = GetForwardHeader(ctx, "X-Forwarded-Host", "")
		if serverName == "" {
			serverName = GetForwardHeader(ctx, "X-Forwarded-Server-Name", _host)
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#EXTM3U") {
			continue
		}

		// 解析 EXTINF 行
		if strings.HasPrefix(line, "#EXTINF") && strings.Contains(line, "group-title") {
			matches := reTvg.FindStringSubmatch(line)
			if len(matches) == 2 {
				tvgID = matches[1]
			} else {
				tvgID = "unknown"
			}
			newLines = append(newLines, line)
			continue
		}

		// 解析 Kodi DRM 标签
		if strings.Contains(line, "w3.clearkey") {
			matches := reDrm.FindStringSubmatch(line)
			if len(matches) == 3 {
				clearkey = matches[1] + ":" + matches[2]
			}
			continue
		}

		// 解析 Kodi DRM 标签
		if strings.Contains(line, "license_key=") {
			infos := strings.Split(line, "license_key=")
			if len(infos) == 2 {
				clearkey = infos[1]
			}
			continue
		}

		if strings.HasPrefix(line, "#KODIPROP") {
			continue
		}

		// 普通流 URL
		u, err := base.Parse(line)
		content_type := "m3u8"
		if strings.Contains(line, ".mpd") {
			content_type = "mpd"
		}
		if err == nil {
			if tvgID == "unknown" || !reValidTvg.MatchString(tvgID) {
				hash := md5.Sum([]byte(line))
				tvgID = hex.EncodeToString(hash[:])
			}
			clearKeysMap[tvgID] = clearkey
			clientsByTvgId[tvgID] = clientsByAlias[alias]
			proxyPath := fmt.Sprintf("%s://%s:%s/drm/proxy/%s/%s/%s",
				schema, serverName, port,
				content_type,
				tvgID,
				strings.Replace(u.String(), "://", "/", 1))
			newLines = append(newLines, proxyPath)

		}
	}
	if ctx != nil {
		ctx.SetContentType("text/plain; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBodyString(strings.Join(newLines, "\n"))
	}
}

var re = regexp.MustCompile(`URI="([^"]+)"`)

func convert_to_proxy_url(proxy_type string, tvgID string, original_url string, proxy_url string) string {
	var finalURI string
	if strings.HasPrefix(original_url, "/") {
		u, err := url.Parse(proxy_url)
		if err == nil {
			base := u.Scheme + "://" + u.Host
			finalURI = base + original_url
		}
	} else if strings.HasPrefix(original_url, "http") {
		finalURI = original_url
	} else {
		idx := strings.LastIndex(proxy_url, "/")
		finalURI = proxy_url[:idx] + "/" + original_url
	}
	return fmt.Sprintf("/drm/proxy/%s/%s/%s", proxy_type, tvgID, strings.Replace(finalURI, "://", "/", 1))
}

func collectBaseURLs(elem *etree.Element) []string {
	var urls []string
	for e := elem; e != nil; e = e.Parent() {
		parent := e.Parent()
		if parent == nil {
			break
		}
		for _, child := range parent.ChildElements() {
			if child.Tag == "BaseURL" {
				// 插入到开头，保证顺序从根到当前
				urls = append([]string{strings.TrimSpace(child.Text())}, urls...)
				break
			}
		}
	}
	return urls
}

func joinBaseAndMedia(baseURLs []string, media string) string {
	var base string
	for _, u := range baseURLs {
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			base = strings.TrimSuffix(u, "/") + "/"
		} else {
			base = path.Join(base, u) + "/" // 确保尾部 /
		}
	}
	return base + media // media 不加 /
}

// 代理流 URL
func proxyStreamURL(ctx *fasthttp.RequestCtx, path string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/drm/proxy/"), "/", 3)
	if len(parts) < 3 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Invalid proxy URL")
		return
	}
	proxy_type := parts[0]
	tvgID := parts[1]
	proxy_url := strings.Replace(parts[2], "http/", "http://", 1)
	proxy_url = strings.Replace(proxy_url, "https/", "https://", 1)
	query := string(ctx.QueryArgs().QueryString())
	if query != "" {
		proxy_url += "?" + query
	}

	client, ok := clientsByTvgId[tvgID]
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		return
	}

	// 直接重定向到原始 URL
	log.Printf("代理下载开始：%s:\n", tvgID)
	proxy_url, resp, err := fetchWithRedirect(client, proxy_url, 5, "")
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetStatusCode(fasthttp.StatusBadGateway)
		ctx.SetBodyString("无法获取内容U")
		return
	}
	log.Printf("代理下载结束：%s:\n", tvgID)
	defer fasthttp.ReleaseResponse(resp)
	body := resp.Body()
	contentType := string(resp.Header.ContentType())
	if proxy_type == "mpd" || contentType == "application/dash+xml" {
		doc := etree.NewDocument()
		doc.ReadFromBytes(body)

		//删除DRM信息
		for _, cp := range doc.FindElements("//ContentProtection") {
			cp.Parent().RemoveChild(cp)
		}

		// 查找所有 SegmentTemplate 节点
		segTemplates := doc.FindElements("//SegmentTemplate")
		for _, st := range segTemplates {
			media := st.SelectAttrValue("media", "")
			if media != "" {
				media = joinBaseAndMedia(collectBaseURLs(st), media)
				media_type := "m4s"
				if strings.Contains(media, "jpg") || strings.Contains(media, "png") {
					media_type = "jpg"
				}
				st.RemoveAttr("media")
				st.CreateAttr("media", convert_to_proxy_url(media_type, tvgID, media, proxy_url))
			}

			init := st.SelectAttrValue("initialization", "")
			if init != "" {
				init = joinBaseAndMedia(collectBaseURLs(st), init)
				st.RemoveAttr("initialization")
				st.CreateAttr("initialization", convert_to_proxy_url("init-m4s", tvgID, init, proxy_url))
			}
		}

		//删除BaseURL
		BaseURLs := doc.FindElements("//BaseURL")
		for _, bu := range BaseURLs {
			parent := bu.Parent() // 获取父节点
			if parent != nil {
				parent.RemoveChild(bu) // 从父节点删除自己
			}
		}

		body, err = doc.WriteToBytes()
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("xml 重写错误")
			return
		}

		if !strings.Contains(path, "mpd") {
			ctx.SetContentType(contentType)
		} else {
			ctx.SetContentType("text/plain; charset=utf-8")
		}
	} else if proxy_type == "m3u8" {
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
					line = re.ReplaceAllString(line, `URI="`+convert_to_proxy_url("init-m4s", tvgID, matches[1], proxy_url)+`"`)
				}
			}

			// 标记上一行是 #EXTINF
			if strings.HasPrefix(line, "#EXTINF") {
				lastLineWasExtInf = true
				newLines = append(newLines, line)
				continue
			}

			// 如果上一行是 #EXTINF，当前行是分片地址，需要代理
			if lastLineWasExtInf && line != "" {
				line = convert_to_proxy_url("m4s", tvgID, line, proxy_url)
				lastLineWasExtInf = false
			}
			newLines = append(newLines, line)
		}
		body = []byte(strings.Join(newLines, "\n"))
		ctx.SetContentType("text/plain; charset=utf-8")
	} else if proxy_type == "init-m4s" {
		body, err = removePsshAndSinfFromBody(body)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("移除 DRM 信息失败")
			return
		}
		ctx.SetContentType(contentType)
	} else if proxy_type == "m4s" {
		if val, ok := clearKeysMap[tvgID]; ok {
			if strings.HasPrefix(val, "http") {
				resp, err = HttpGetWithUA(client, val, "0.11")
				if err != nil || resp.StatusCode() != fasthttp.StatusOK {
					ctx.SetStatusCode(fasthttp.StatusBadGateway)
					ctx.SetBodyString("无法获取 M3U")
					return
				}
				val = string(resp.Body())
				clearKeysMap[tvgID] = val
			}
			if strings.HasPrefix(val, "{\"keys\"") {
				var jwk JWKSet
				if err := json.Unmarshal([]byte(val), &jwk); err != nil {
					panic(err)
				}

				for _, key := range jwk.Keys {
					kid, _ := base64DecodeWithPad(key.Kid)
					k, _ := base64DecodeWithPad(key.K)
					val = hex.EncodeToString(kid) + ":" + hex.EncodeToString(k)
				}
			}
			kid_key := strings.Split(val, ":")
			if len(kid_key) != 2 {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("密钥格式错误," + val)
				return
			}
			key_bytes, err := hex.DecodeString(kid_key[1])
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("密钥格式错误")
				return
			}
			body, err = decryptWidevineFromBody(body, key_bytes)
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("DRM 解密信息失败")
				return
			}
			ctx.SetContentType(contentType)
		} else {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("找不到对应的clearKey")
			return
		}
	} else {
		ctx.SetContentType(contentType)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(body)
	log.Printf("代理结束: %s, 大小=%d\n", tvgID, len(body))
}
