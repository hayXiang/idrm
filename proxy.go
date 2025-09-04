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

	"os"

	"github.com/beevik/etree"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

// ---------- 数据结构 ----------
type StreamConfig struct {
	Name              string   `json:"name"`
	URL               string   `json:"url"`
	Headers           []string `json:"headers"`
	LicenseUrlHeaders []string `json:"license_url_headers"`
	Proxy             string   `json:"proxy"`
}

// ---------- 支持多次传参的 flag ----------
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

var (
	configFile  string
	name        string
	bindAddr    string
	singleInput string
	headers     multiFlag
	proxyURL    string
	publishAddr string

	providerByTvgId   = make(map[string]string)
	configsByProvider = make(map[string]StreamConfig)
	clientsByProvider = make(map[string]*fasthttp.Client)
	DEFAULT_CLIENT    *fasthttp.Client
)

var version = "1.0.0.1"

func loadConfigFile(path string) ([]StreamConfig, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg []StreamConfig
	if err := json.Unmarshal(f, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func newFastHTTPClient(socks5_url string) *fasthttp.Client {
	client := &fasthttp.Client{
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    10 * time.Second,
		MaxConnsPerHost: 500,
	}

	if socks5_url != "" {
		u, err := url.Parse(socks5_url)
		if err != nil {
			log.Fatalf("无法创建 SOCKS5 代理: %v", err)
		}
		var auth *proxy.Auth = nil
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{
				User:     u.User.Username(),
				Password: password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
		if err != nil {
			log.Fatalf("无法创建 SOCKS5 代理: %v", err)
		}
		client.Dial = func(addr string) (net.Conn, error) {
			conn, err := dialer.Dial("tcp", addr)
			if err != nil {
				return nil, err
			}
			// 给连接设置读取和写入超时
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			return conn, nil
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

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&configFile, "c", "", "配置文件 (JSON)。使用这种模式，下面的--name, --input, --header --proxy将无效")
	flag.StringVar(&bindAddr, "listen", "127.0.0.1:1234", "代理服务器监听端口")
	flag.StringVar(&bindAddr, "l", "127.0.0.1:1234", "代理服务器监听端口 (简写)")
	flag.StringVar(&name, "name", "index", "provider 的名称")
	flag.StringVar(&singleInput, "input", "", "单个流 URL")
	flag.StringVar(&singleInput, "i", "", "单个流 URL（简写）")
	flag.Var(&headers, "header", "HTTP 请求头，可多次指定")
	flag.StringVar(&proxyURL, "proxy", "", "代理设置 (SOCKS5)")
	flag.StringVar(&publishAddr, "publish", "", "发布地址的前缀(公网可以访问的地址）,例如:https://live.9999.eu.org:443")

	flag.Parse()

	name = strings.TrimSpace(name)
	proxyURL = strings.TrimSpace(proxyURL)
	bindAddr = strings.TrimSpace(bindAddr)
	publishAddr = strings.TrimSpace(publishAddr)

	// 处理监听地址
	if !strings.Contains(bindAddr, ":") {
		bindAddr = "127.0.0.1:" + bindAddr
	} else if strings.HasPrefix(bindAddr, ":") {
		bindAddr = "127.0.0.1" + bindAddr
	}

	var configs []StreamConfig
	var err error
	if configFile != "" {
		configs, err = loadConfigFile(configFile)
		if err != nil {
			log.Fatalf("配置文件加载失败: %v", err)
		}
	} else if singleInput != "" {
		configs = []StreamConfig{
			{
				Name:    name,
				URL:     singleInput,
				Headers: headers,
				Proxy:   proxyURL,
			},
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	for _, config := range configs {
		configsByProvider[config.Name] = config
		clientsByProvider[config.Name] = newFastHTTPClient(config.Proxy)
	}
	DEFAULT_CLIENT = newFastHTTPClient("")

	var enablePprof bool
	var pprofAddr string

	flag.BoolVar(&enablePprof, "pprof-enable", false, "Enable pprof HTTP server")
	flag.StringVar(&pprofAddr, "pprof-addr", "localhost:7070", "pprof listen address")
	for _, config := range configs {
		go func() {
			loadM3u(nil, config.Name)
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

	log.Printf("代理服务器启动在：%s, 当前版本：%s", bindAddr, version)
	if err := fasthttp.ListenAndServe(bindAddr, requestHandler); err != nil {
		log.Fatalf("ListenAndServe error: %s", err)
	}
}

// fetchWithRedirect 发起 GET 请求，自动跟随重定向（最多 maxRedirects 次）
func fetchWithRedirect(client *fasthttp.Client, startURL string, maxRedirects int, headers []string) (string, *fasthttp.Response, error) {
	currentURL := startURL

	for i := 0; i < maxRedirects; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(currentURL)
		req.Header.SetMethod("GET")
		if len(headers) == 0 {
			req.Header.Set("User-Agent", "okhttp/4.12.0")
		} else {
			for _, head := range headers {
				key_value := strings.Split(head, ":")
				if len(key_value) == 2 {
					req.Header.Set(key_value[0], strings.TrimSpace(key_value[1]))
				}
			}
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

func HttpGetWithUA(client *fasthttp.Client, url string, headers []string) (*fasthttp.Response, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()

	req.SetRequestURI(url)
	if len(headers) == 0 {
		req.Header.Set("User-Agent", "okhttp/4.12.0")
	} else {
		for _, head := range headers {
			key_value := strings.Split(head, ":")
			if len(key_value) == 2 {
				req.Header.Set(key_value[0], strings.TrimSpace(key_value[1]))
			}
		}

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
		loadM3u(ctx, "")
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
func loadM3u(ctx *fasthttp.RequestCtx, name string) {
	if ctx != nil {
		name = getAliasFromPath(string(ctx.URI().Path()))
	}
	config, ok := configsByProvider[name]
	if !ok {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("不存在数据")
		}
		return
	}
	log.Printf("开始加载M3u: %s, %s", name, config.URL)
	var count = 0
	var body []byte
	if strings.HasPrefix(config.URL, "http") {
		resp, err := HttpGetWithUA(DEFAULT_CLIENT, config.URL, []string{})
		if err != nil || resp.StatusCode() != fasthttp.StatusOK {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("无法获取 M3U")
			}
			log.Printf("[ERROR]无法获取 M3U: %s, %s, %v", name, config.URL, err)
			return
		}
		defer fasthttp.ReleaseResponse(resp)
		body = resp.Body()
	} else {
		// 本地文件
		f, err := os.ReadFile(config.URL)
		if err != nil {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("无法读取本地 M3U")
			}
			log.Printf("[ERROR]无法读取本地 M3U: %s, %s", name, config.URL)
			return
		}
		body = f
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) > 0 && !strings.HasPrefix(lines[0], "#EXT") {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("非法的M3U内容")
		}
		log.Printf("[ERROR]非法的M3U内容: %s, %s", name, config.URL)
		if len(body) > 500 {
			log.Printf("[ERROR] 非法M3U内容过长: %s, 前500字符: %s", name, string(body[:500]))
		} else {
			log.Printf("[ERROR] 非法M3U内容: %s, %s", name, string(body))
		}
		return
	}
	base, _ := url.Parse(config.URL)

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
			providerByTvgId[tvgID] = name
			prefixAddress := fmt.Sprintf("%s://%s:%s", schema, serverName, port)
			if publishAddr != "" {
				prefixAddress = publishAddr
			}
			proxyPath := fmt.Sprintf("%s/drm/proxy/%s/%s/%s",
				prefixAddress,
				content_type,
				tvgID,
				strings.Replace(u.String(), "://", "/", 1))
			newLines = append(newLines, proxyPath)
			count = count + 1
		}
	}
	log.Printf("结束加载M3u: %s, 一共%d个频道, 访问地址: http://%s/%s.m3u", name, count, bindAddr, name)
	if publishAddr != "" {
		log.Printf("结束加载M3u: %s, 发布地址: %s/%s.m3u", name, publishAddr, name)
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

	provider, ok := providerByTvgId[tvgID]
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id, not found provider")
		return
	}

	client, ok := clientsByProvider[provider]
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		return
	}

	// 直接重定向到原始 URL
	log.Printf("下载开始：%s，%s", tvgID, proxy_url)
	start := time.Now()
	proxy_url, resp, err := fetchWithRedirect(client, proxy_url, 5, configsByProvider[provider].Headers)
	log.Printf("下载结束：%s，%s, 耗时：%d ms", tvgID, proxy_url, time.Since(start).Milliseconds())
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetBodyString("无法获取内容")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			log.Printf("[ERROR] 下载错误：%s，%s, %v", tvgID, proxy_url, err)
		} else {
			ctx.SetStatusCode(resp.StatusCode())
			log.Printf("[ERROR] 下载错误：%s，%s, 状态码: %d", tvgID, proxy_url, resp.StatusCode())
		}
		return
	}
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
			log.Printf("[ERROR] xml 重写错误 %s，%s, %s", tvgID, proxy_url, err)
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
			log.Printf("[ERROR] 移除 DRM 信息失败， %s，%s, %s", tvgID, proxy_url, err)
			return
		}
		ctx.SetContentType(contentType)
	} else if proxy_type == "m4s" {
		if val, ok := clearKeysMap[tvgID]; ok {
			if strings.HasPrefix(val, "http") {
				resp, err = HttpGetWithUA(client, val, configsByProvider[provider].LicenseUrlHeaders)
				if err != nil || resp.StatusCode() != fasthttp.StatusOK {
					ctx.SetStatusCode(fasthttp.StatusBadGateway)
					ctx.SetBodyString("无法获取 license")
					log.Printf("[ERROR] 无法获取 license， %s，%s, %v", tvgID, val, err)
					return
				}
				val = string(resp.Body())
				clearKeysMap[tvgID] = val
			}
			if strings.Contains(val, "kty") && strings.Contains(val, "keys") {
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
				log.Printf("[ERROR] 密钥格式错误， %s，%s", tvgID, proxy_url)
				return
			}
			key_bytes, err := hex.DecodeString(kid_key[1])
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("密钥格式错误")
				log.Printf("[ERROR] 密钥格式错误， %s，%s, %s", tvgID, proxy_url, err)
				return
			}
			body, err = decryptWidevineFromBody(body, key_bytes)
			if err != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("DRM 解密信息失败")
				log.Printf("[ERROR] DRM 解密信息失败，%s，%s, %s", tvgID, proxy_url, err)
				return
			}
			ctx.SetContentType(contentType)
		} else {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("找不到对应的clearKey")
			log.Printf("[ERROR] 找不到对应的clearKey， %s，%s", tvgID, proxy_url)
			return
		}
	} else {
		ctx.SetContentType(contentType)
	}
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(body)
	log.Printf("代理结束: %s, %s, 耗时：%d ms, 大小=%d,", tvgID, proxy_url, time.Since(start).Milliseconds(), len(body))
}
