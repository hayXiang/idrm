package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"path"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"os"

	"github.com/beevik/etree"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

// ---------- 数据结构 ----------
type StreamConfig struct {
	Name                     string   `json:"name"`
	URL                      string   `json:"url"`
	Headers                  []string `json:"headers"`
	UserAgent                *string  `json:"user-agent"`
	LicenseUrlHeaders        []string `json:"license-url-headers"`
	Proxy                    string   `json:"proxy"`
	M3uProxy                 string   `json:"m3u-proxy"`
	M3uUserAgent             *string  `json:"m3u-user-agent"`
	BestQuality              *bool    `json:"best-quality"`
	ToFmp4OverHls            *bool    `json:"to-hls"`
	SpeedUp                  *bool    `json:"speed-up"`
	HttpTimeout              *int     `json:"http-timeout"`
	ManifestCacheExpire      *int     `json:"cache-manifest"`
	SegmentMemoryCacheExpire *int     `json:"cache-segment-memory"`
	SegmentFileCacheExpire   *int     `json:"cache-segment-file"`
	CacheDir                 *string  `json:"cache-dir"`
	DrmType                  *string  `json:"drm-type"`
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
	configFile               string
	name                     string
	bindAddr                 string
	singleInput              string
	headers                  multiFlag
	proxyURL                 string
	publishAddr              string
	userAgent                string
	m3uProxy                 string
	m3uUserAgent             string
	bestQuality              bool
	toFmp4OverHls            bool
	speedUp                  bool
	maxMemory                int64
	gcInterval               int
	httpTimeout              int
	manifestCacheExpire      int
	segmentMemoryCacheExpire int
	segmentFileCacheExpire   int
	cacheDir                 string
	drmType                  string

	providerByTvgId         = sync.Map{} // map[tvgID]providerName
	configsByProvider       = make(map[string]*StreamConfig)
	clientsByProvider       = make(map[string]*fasthttp.Client)
	m3uClientByProvider     = make(map[string]*fasthttp.Client)
	manifestCacheByProvider = make(map[string]*MyCache)
	segmentCacheByProvider  = make(map[string]*MyCache)
	hlsByTvgId              = sync.Map{}
	rawUrlByTvgId           = sync.Map{}
	hlsTypeByTvgId          = sync.Map{}
)

var version = "1.0.0.8"

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

func newFastHTTPClient(socks5_url string, timeout int) *fasthttp.Client {
	client := &fasthttp.Client{
		ReadTimeout:     time.Second * time.Duration(timeout),
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

func validateHeaderLine(line string) error {
	// 必须包含冒号
	if !strings.Contains(line, ":") {
		return errors.New("header 缺少冒号")
	}

	// 拆分 key 和 value
	parts := strings.SplitN(line, ":", 2)
	key := strings.TrimSpace(parts[0])

	if key == "" {
		return errors.New("header key 为空")
	}
	return nil
}

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	flag.StringVar(&configFile, "c", "", "配置文件 (JSON)。使用这种模式，下面的--name, --input, --header, --proxy --user-agent 将无效")
	flag.StringVar(&bindAddr, "listen", "127.0.0.1:1234", "代理服务器监听端口")
	flag.StringVar(&bindAddr, "l", "127.0.0.1:1234", "代理服务器监听端口 (简写)")
	flag.StringVar(&name, "name", "default", "provider 的名称")
	flag.StringVar(&singleInput, "input", "", "单个流 URL")
	flag.StringVar(&singleInput, "i", "", "单个流 URL（简写）")
	flag.Var(&headers, "header", "HTTP 请求头，可多次指定")
	flag.StringVar(&userAgent, "user-agent", "okhttp/4.12.0", "自定义 User-Agent, 优先级高于 header")
	flag.StringVar(&userAgent, "A", "okhttp/4.12.0", "自定义 User-Agent, 优先级高于 header (简写)")
	flag.StringVar(&proxyURL, "proxy", "", "MPD或者M3U8代理设置 (SOCKS5)")
	flag.StringVar(&publishAddr, "publish", "", "发布地址的前缀(公网可以访问的地址）,例如:https://live.9999.eu.org:443")
	flag.StringVar(&m3uProxy, "m3u-proxy", "", "M3U 请求的代理设置 (SOCKS5)")
	flag.StringVar(&m3uUserAgent, "m3u-user-agent", "okhttp/4.12.0", "M3U 请求的 User-Agent")
	flag.BoolVar(&bestQuality, "best-quality", true, "仅保留最高码率的音视频")
	flag.BoolVar(&toFmp4OverHls, "to-hls", false, "将dash转成fmp4 over hls")
	flag.BoolVar(&speedUp, "speed-up", false, "预加载分片")
	flag.Int64Var(&maxMemory, "max-memory", 0, "最大内存使用，单位MB，0表示不限制, 最小值100MB")
	flag.IntVar(&gcInterval, "auto-gc", 30, "自动垃圾回收间隔，单位秒，0表示不启用, 最小值5秒")
	flag.IntVar(&httpTimeout, "http-timeout", 15, "默认http请求超时")
	flag.StringVar(&cacheDir, "cache-dir", "./", "cache 文件的保存路径，默认当前路径")
	flag.IntVar(&manifestCacheExpire, "cache-manifest", -1, "mpd或者m3u8缓存过期时间，单位秒,-1 表示不开启")
	flag.IntVar(&segmentMemoryCacheExpire, "cache-segment-memory", -1, "ts或者m4s缓存短期过期时间，单位秒, -1 表示不开启")
	flag.IntVar(&segmentFileCacheExpire, "cache-segment-file", -1, "ts或者m4s缓存文件最大存活时间，单位秒,-1 表示不开启")
	flag.StringVar(&drmType, "drm-type", "widevine", "DRM的类型，决定了默认的解密方式，程序也会去校验m3u8的DRM类型，自动调整")

	var enablePprof bool
	var pprofAddr string

	flag.BoolVar(&enablePprof, "pprof-enable", false, "Enable pprof HTTP server")
	flag.StringVar(&pprofAddr, "pprof-addr", "localhost:7070", "pprof listen address")

	flag.Parse()

	if gcInterval > 0 {
		if gcInterval < 5 {
			gcInterval = 5
		}
		startAutoGC(time.Duration(gcInterval) * time.Second)
	}

	if maxMemory > 0 {
		if maxMemory < 100 {
			maxMemory = 100
		}
		debug.SetMemoryLimit(maxMemory << 20)
	}
	userSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "user-agent" || f.Name == "A" {
			userSet = true
		}
	})

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
		var ua string = "okhttp/4.12.0"
		for i := range configs {
			if configs[i].M3uUserAgent == nil {
				configs[i].M3uUserAgent = &ua
			}

			if configs[i].BestQuality == nil {
				configs[i].BestQuality = &bestQuality
			}

			if configs[i].ToFmp4OverHls == nil {
				configs[i].ToFmp4OverHls = &toFmp4OverHls
			}

			if configs[i].HttpTimeout == nil {
				configs[i].HttpTimeout = &httpTimeout
			}

			if configs[i].ManifestCacheExpire == nil {
				configs[i].ManifestCacheExpire = &manifestCacheExpire
			}

			if configs[i].SegmentFileCacheExpire == nil {
				configs[i].SegmentFileCacheExpire = &segmentFileCacheExpire
			}

			if configs[i].SegmentMemoryCacheExpire == nil {
				configs[i].SegmentMemoryCacheExpire = &segmentMemoryCacheExpire
			}

			if configs[i].SpeedUp == nil {
				configs[i].SpeedUp = &speedUp
			}

			if configs[i].DrmType == nil {
				configs[i].DrmType = &drmType
			}
		}
	} else if singleInput != "" {
		var us *string = nil
		if userSet {
			us = &userAgent
		}
		configs = []StreamConfig{
			{
				Name:                     name,
				URL:                      singleInput,
				Headers:                  headers,
				UserAgent:                us,
				Proxy:                    proxyURL,
				M3uProxy:                 m3uProxy,
				M3uUserAgent:             &m3uUserAgent,
				BestQuality:              &bestQuality,
				ToFmp4OverHls:            &toFmp4OverHls,
				HttpTimeout:              &httpTimeout,
				SegmentMemoryCacheExpire: &segmentMemoryCacheExpire,
				SegmentFileCacheExpire:   &segmentFileCacheExpire,
				ManifestCacheExpire:      &manifestCacheExpire,
				SpeedUp:                  &speedUp,
				DrmType:                  &drmType,
			},
		}
	} else {
		flag.Usage()
		os.Exit(1)
	}

	// 处理 User-Agent 优先级
	for i := range configs {
		var user_agent_index = -1
		for j, h := range configs[i].Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) != 2 {
				continue // 非法 Header 跳过
			}
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			if key == "user-agent" {
				user_agent_index = j
				if configs[i].UserAgent == nil {
					configs[i].UserAgent = &value
				}
				break
			}
		}
		ua := "okhttp/4.12.0"
		if configs[i].UserAgent == nil {
			configs[i].UserAgent = &ua
		}
		if user_agent_index != -1 {
			// 覆盖已有的 User-Agent
			configs[i].Headers[user_agent_index] = "User-Agent: " + *configs[i].UserAgent
		} else {
			// 添加新的 User-Agent
			configs[i].Headers = append(configs[i].Headers, "User-Agent: "+*configs[i].UserAgent)
		}
	}

	for _, config := range configs {
		if config.Headers != nil {
			for _, line := range config.Headers {
				if err := validateHeaderLine(line); err != nil {
					log.Fatalf("无效的 header 格式: %s, 错误: %v.", line, err)
				}
			}
		}
	}

	if !strings.HasSuffix(cacheDir, "/") {
		cacheDir += "/"
	}
	for _, config := range configs {
		configsByProvider[config.Name] = &config
		clientsByProvider[config.Name] = newFastHTTPClient(config.Proxy, *config.HttpTimeout)
		m3uClientByProvider[config.Name] = newFastHTTPClient(config.M3uProxy, 30)
		if *config.ManifestCacheExpire >= 0 {
			manifestCacheByProvider[config.Name] = NewMyCache(cacheDir+"idrm-cache/"+config.Name+"/manifest", *config.ManifestCacheExpire, -1)
		}

		if *config.SegmentFileCacheExpire >= 0 || *config.SegmentMemoryCacheExpire >= 0 || *config.SpeedUp {
			if *config.SegmentMemoryCacheExpire < 10 {
				*config.SegmentMemoryCacheExpire = 10
			}
			segmentCacheByProvider[config.Name] = NewMyCache(cacheDir+"idrm-cache/"+config.Name, *config.SegmentMemoryCacheExpire, *config.SegmentFileCacheExpire)
		}
	}

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
func fetchWithRedirect(client *fasthttp.Client, startURL string, maxRedirects int, headers []string, timeout int) (string, *fasthttp.Response, error) {
	currentURL := startURL

	for i := 0; i < maxRedirects; i++ {
		req := fasthttp.AcquireRequest()
		resp := fasthttp.AcquireResponse()

		req.SetRequestURI(currentURL)
		req.Header.SetMethod("GET")
		for _, head := range headers {
			key_value := strings.Split(head, ":")
			if len(key_value) == 2 {
				req.Header.Set(key_value[0], strings.TrimSpace(key_value[1]))
			}
		}

		err := client.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
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

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.Path())

	switch {
	case strings.HasPrefix(path, "/drm/proxy/"):
		proxyStreamURL(ctx, path)
	case strings.HasSuffix(path, ".m3u"):
		loadM3u(ctx, "")
	case strings.HasPrefix(path, "/stats/cache"):
		CacheStatsHandler(ctx)
	default:
		ctx.SetStatusCode(fasthttp.StatusNotFound)
		ctx.SetBodyString("Not Found")
	}
}

var reTvg = regexp.MustCompile(`tvg-id="([^"]+)"`)
var reDrm = regexp.MustCompile(`drm_legacy=org\.w3\.clearkey\|([0-9a-fA-F]+):([0-9a-fA-F]+)`)
var reValidTvg = regexp.MustCompile(`^[0-9a-zA-Z_-]+$`)
var clearKeysMap = sync.Map{} // map[tvgID]clearkey

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
	log.Printf("开始加载M3u: %s, %s, User-Agent:%s", name, config.URL, *config.UserAgent)
	var count = 0
	var body []byte
	if strings.HasPrefix(config.URL, "http") {
		resp, err := HttpGetWithUA(m3uClientByProvider[name], config.URL, []string{"user-agent: " + *config.M3uUserAgent}, 30)
		if err != nil || resp.StatusCode() != fasthttp.StatusOK {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
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

			clearKeysMap.Store(tvgID, clearkey)
			providerByTvgId.Store(tvgID, name)

			prefixAddress := fmt.Sprintf("%s://%s:%s", schema, serverName, port)
			if publishAddr != "" {
				prefixAddress = publishAddr
			}
			var proxyPath = ""
			if *(configsByProvider[name].ToFmp4OverHls) && content_type == "mpd" {
				var suffix = ""
				if strings.Contains(suffix, ".m3u8") {
					suffix = ".m3u8"
				}
				if strings.Contains(suffix, ".mpd") {
					suffix = ".mpd"
				}
				if *configsByProvider[name].ToFmp4OverHls {
					suffix = ".m3u8"
				}
				proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/index%s",
					prefixAddress,
					content_type,
					tvgID,
					suffix,
				)
			} else {
				proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/%s",
					prefixAddress,
					content_type,
					tvgID,
					strings.Replace(u.String(), "://", "/", 1))
			}
			rawUrlByTvgId.Store(tvgID, u.String())
			newLines = append(newLines, proxyPath)
			count = count + 1
		}
	}
	var extra = ""
	if publishAddr != "" {
		extra += fmt.Sprintf(", 发布地址: %s/%s.m3u", publishAddr, name)
	}
	log.Printf("结束加载M3u: %s, 一共%d个频道, 访问地址: http://%s/%s.m3u%s", name, count, bindAddr, name, extra)

	if ctx != nil {
		ctx.SetStatusCode(fasthttp.StatusOK)
		resposneBody(ctx, []byte(strings.Join(newLines, "\n")), "text/plain; charset=utf-8")
	}
}

var M3U8_INIT_REGEXP = regexp.MustCompile(`URI="([^"]+)"`)

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

func convert_to_proxy_url(proxy_type string, tvgID string, targetUrl string, baseUrl string) string {
	return fmt.Sprintf("/drm/proxy/%s/%s/%s", proxy_type, tvgID, strings.Replace(resolveURL(targetUrl, baseUrl), "://", "/", 1))
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

func formatSize(size int64) string {
	const (
		KB = 1024
		MB = 1024 * KB
	)

	if size >= MB {
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	} else if size >= KB {
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	}
	return fmt.Sprintf("%d B", size)
}

func formatDuration(d time.Duration) string {
	ms := d.Milliseconds() // 转换为毫秒
	sec := d.Seconds()     // 转换为秒

	if ms >= 1000 {
		return fmt.Sprintf("%.2f s", sec) // 大于等于 1 秒显示秒
	}
	return fmt.Sprintf("%d ms", ms) // 小于 1 秒显示毫秒
}

func filterHighestAV(body string) string {
	lines := strings.Split(body, "\n")

	var maxVideoBW int64 = -1
	var bestVideoINF, bestVideoURI, bestAudioGroup, bestCCGroup string

	// 存全局标签 / 图片轨道
	var globalTags, imageTracks []string

	// 找最高码率视频
	for i := 0; i < len(lines)-1; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// 收集全局标签
		if strings.HasPrefix(line, "#EXT-X-VERSION") ||
			strings.HasPrefix(line, "#EXT-X-INDEPENDENT-SEGMENTS") {
			globalTags = append(globalTags, line)
		}

		// 收集图片轨道
		if strings.HasPrefix(line, "#EXT-X-IMAGE-STREAM-INF") {
			imageTracks = append(imageTracks, line)
			if i+1 < len(lines) && !strings.HasPrefix(lines[i+1], "#") {
				imageTracks = append(imageTracks, lines[i+1])
			}
		}

		// 视频流
		if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			attrs := strings.Split(line[len("#EXT-X-STREAM-INF:"):], ",")
			var bw int64
			var audioGroup, ccGroup string
			for _, a := range attrs {
				kv := strings.SplitN(strings.TrimSpace(a), "=", 2)
				if len(kv) == 2 {
					key := strings.ToUpper(kv[0])
					val := strings.Trim(kv[1], `"`)
					switch key {
					case "BANDWIDTH":
						fmt.Sscanf(val, "%d", &bw)
					case "AUDIO":
						audioGroup = val
					case "CLOSED-CAPTIONS":
						ccGroup = val
					}
				}
			}
			uri := strings.TrimSpace(lines[i+1])
			if bw > maxVideoBW {
				maxVideoBW = bw
				bestVideoINF = line
				bestVideoURI = uri
				bestAudioGroup = audioGroup
				bestCCGroup = ccGroup
			}
		}
	}

	// 找对应的音频
	var bestAudioLine string
	if bestAudioGroup != "" {
		var maxABW int64 = -1
		re := regexp.MustCompile(`BANDWIDTH=(\d+)`)
		for _, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-MEDIA:") &&
				strings.Contains(line, "TYPE=AUDIO") &&
				strings.Contains(line, fmt.Sprintf("GROUP-ID=\"%s\"", bestAudioGroup)) {
				m := re.FindStringSubmatch(line)
				var bw int64
				if len(m) == 2 {
					if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
						bw = v
					}
				}
				if bw > maxABW {
					maxABW = bw
					bestAudioLine = line
				}
			}
		}
	}

	// 找对应的字幕
	var ccLines []string
	if bestCCGroup != "" && bestCCGroup != "NONE" {
		for _, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-MEDIA:") &&
				strings.Contains(line, "TYPE=CLOSED-CAPTIONS") &&
				strings.Contains(line, fmt.Sprintf("GROUP-ID=\"%s\"", bestCCGroup)) {
				ccLines = append(ccLines, line)
			}
		}
	}

	// 拼结果
	var sb strings.Builder
	sb.WriteString("#EXTM3U\n")
	for _, g := range globalTags {
		sb.WriteString(g + "\n")
	}
	if bestAudioLine != "" {
		sb.WriteString(bestAudioLine + "\n")
	}
	for _, l := range ccLines {
		sb.WriteString(l + "\n")
	}
	if bestVideoINF != "" {
		sb.WriteString(bestVideoINF + "\n" + bestVideoURI + "\n")
	}
	for _, img := range imageTracks {
		sb.WriteString(img + "\n")
	}
	return sb.String()
}

// 字符串转 int 辅助函数
func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// 判断 AdaptationSet 是否有有效字幕
func hasSubtitle(adap *etree.Element) bool {
	contentType := adap.SelectAttrValue("contentType", "")
	rep := adap.FindElement("Representation")
	segTemp := adap.FindElement("SegmentTemplate")
	if rep == nil || segTemp == nil {
		return false
	}

	mimeType := rep.SelectAttrValue("mimeType", "")
	codecs := rep.SelectAttrValue("codecs", "")
	if contentType == "text" || contentType == "subtitle" ||
		mimeType == "application/ttml+xml" || strings.Contains(codecs, "stpp") {
		return true
	}
	return false
}

func periodHasSubtitle(period *etree.Element) bool {
	adaps := period.FindElements("AdaptationSet")
	for _, adap := range adaps {
		if hasSubtitle(adap) { // 前面定义的 hasSubtitle
			return true
		}
	}
	return false
}

func modifyHLS(body []byte, tvgID, proxyURL string, bestQuality bool) []byte {
	strBody := string(body)

	// 如果启用最高画质过滤
	if bestQuality && strings.Contains(strBody, "#EXT-X-STREAM-INF:") {
		strBody = filterHighestAV(strBody)
	}

	lines := strings.Split(strBody, "\n")
	var newLines []string
	var lastLineWasExtInf bool

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// 跳过 KEY（你这里是直接忽略的）
		if strings.HasPrefix(line, "#EXT-X-KEY") {
			continue
		}

		// 替换 init-m4s (EXT-X-MAP)
		if strings.HasPrefix(line, "#EXT-X-MAP:") {
			matches := M3U8_INIT_REGEXP.FindStringSubmatch(line)
			if len(matches) == 2 {
				newURI := convert_to_proxy_url("init-m4s", tvgID, matches[1], proxyURL)
				line = M3U8_INIT_REGEXP.ReplaceAllString(line, `URI="`+newURI+`"`)
			}
		}

		// 如果上一行是 EXTINF → 当前行是分片地址
		if lastLineWasExtInf && !strings.HasPrefix(line, "#") {
			line = convert_to_proxy_url("m4s", tvgID, line, proxyURL)
			lastLineWasExtInf = false
		}

		if strings.HasPrefix(line, "#EXTINF") {
			lastLineWasExtInf = true
		}

		newLines = append(newLines, line)
	}

	return []byte(strings.Join(newLines, "\n"))
}

func modifyMpd(provider string, tvgId string, url string, body []byte) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadFromBytes(body)

	if mpd := doc.FindElement("//MPD"); mpd != nil {
		// 删除 DRM 命名空间
		mpd.RemoveAttr("xmlns:cenc")
		mpd.RemoveAttr("xmlns:mspr")
		// 保留必要的其他命名空间
		// 比如 xmlns, xmlns:xsi, xmlns:scte35
	}

	//只保留最后一个
	periods := doc.FindElements("//Period")
	if len(periods) > 1 {
		for i := 0; i < len(periods)-1; i++ {
			parent := periods[i].Parent()
			if parent != nil {
				parent.RemoveChild(periods[i])
			}
		}
	}

	//删除image
	adpsets := doc.FindElements("//AdaptationSet")
	for _, adp := range adpsets {
		mimeTpye := adp.SelectAttrValue("mimeType", "")
		if strings.HasPrefix(mimeTpye, "image/") {
			parent := adp.Parent()
			if parent != nil {
				parent.RemoveChild(adp)
			}
		}
	}

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
			st.CreateAttr("media", convert_to_proxy_url(media_type, tvgId, media, url))
		}

		init := st.SelectAttrValue("initialization", "")
		if init != "" {
			init = joinBaseAndMedia(collectBaseURLs(st), init)
			st.RemoveAttr("initialization")
			st.CreateAttr("initialization", convert_to_proxy_url("init-m4s", tvgId, init, url))
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

	if *(configsByProvider[provider].BestQuality) {
		// --- 保留最高码率 Representation ---
		for _, period := range doc.FindElements("//Period") {
			for _, aset := range period.FindElements("AdaptationSet") {
				reps := aset.FindElements("Representation")
				if len(reps) == 0 {
					continue
				}

				// 按 bandwidth 排序，最高码率放前
				sort.Slice(reps, func(i, j int) bool {
					bi := reps[i].SelectAttrValue("bandwidth", "0")
					bj := reps[j].SelectAttrValue("bandwidth", "0")
					return atoi(bi) > atoi(bj)
				})

				// 只保留最高码率
				for i := 1; i < len(reps); i++ {
					aset.RemoveChild(reps[i])
				}
			}
		}
	}

	return doc.WriteToBytes()
}

func resposneBody(ctx *fasthttp.RequestCtx, data []byte, contentType string) error {
	reader := bytes.NewReader(data) // data 是你缓存的分片
	ctx.SetContentType(contentType)
	w := ctx.Response.BodyWriter() // 直接写到底层连接
	_, err := io.Copy(w, reader)   // 边读边写
	return err
}

var rm = NewRequestManager()

// 代理流 URL
func proxyStreamURL(ctx *fasthttp.RequestCtx, path string) {
	parts := strings.SplitN(strings.TrimPrefix(path, "/drm/proxy/"), "/", 3)
	if len(parts) < 3 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Invalid proxy URL")
		return
	}
	query := string(ctx.QueryArgs().QueryString())
	proxy_type := parts[0]
	tvgID := parts[1]
	var proxy_url = ""
	if !strings.HasPrefix(parts[2], "index.") {
		proxy_url = strings.Replace(parts[2], "http/", "http://", 1)
		proxy_url = strings.Replace(proxy_url, "https/", "https://", 1)
		if query != "" {
			proxy_url += "?" + query
		}
		proxy_url = strings.Replace(proxy_url, "?debug", "", 1)
		proxy_url = strings.Replace(proxy_url, "&debug", "", 1)
	} else {
		raw_url, ok := rawUrlByTvgId.Load(tvgID)
		if !ok {
			ctx.SetStatusCode(fasthttp.StatusBadRequest)
			ctx.SetBodyString("invalid tvg id, not found")
			return
		}
		proxy_url = raw_url.(string)
	}

	log.Printf("代理开始：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)

	provider, ok := providerByTvgId.Load(tvgID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id, not found provider")
		return
	}

	client, ok := clientsByProvider[provider.(string)]
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		return
	}

	config := configsByProvider[provider.(string)]
	raw_url, ok := rawUrlByTvgId.Load(tvgID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		return
	}

	if *config.SpeedUp || *config.ToFmp4OverHls {
		startOrResetUpdater(provider.(string), tvgID, raw_url.(string), client, config, 2*time.Second)
	}

	if proxy_type == "hls" {
		hls_list, ok := hlsByTvgId.Load(tvgID)
		if ok {
			body := []byte(hls_list.(map[string]string)[proxy_url])
			contentType := "application/vnd.apple.mpegurl"
			ctx.Response.Header.Set("Cache-Control", "no-cache")
			ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBody(body)
			if strings.Contains(query, "debug") {
				contentType = "text/plain; charset=utf-8"
			}
			ctx.SetContentType(contentType)
		}
		return
	}

	cache := manifestCacheByProvider[provider.(string)]
	if proxy_type == "m4s" {
		cache = segmentCacheByProvider[provider.(string)]
	}

	if cache != nil {
		data, dataType, _, _ := cache.Get(proxy_url)
		if data != nil {
			log.Printf("资源hit：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.Response.Header.Set("IDRM-CACHE", "HIT")
			resposneBody(ctx, data, dataType)
			return
		}
	}

	if cache != nil {
		if canRequest, waitCh := rm.TryRequest(proxy_url); !canRequest {
			WaitOrRedirect(
				ctx,
				proxy_url,
				waitCh,
				1*time.Second,        // 最大等待时间
				100*time.Millisecond, // 每次检查间隔
				func(key string) ([]byte, string, bool) {
					if cache == nil {
						return nil, "", false
					}
					data, dataType, _, _ := cache.Get(key)
					return data, dataType, data != nil
				},
				//ON HIT
				func(ctx *fasthttp.RequestCtx, data []byte, dataType string) {
					log.Printf("资源Hit：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
					resposneBody(ctx, data, dataType)
				},
				//ON TIMEOUT
				func() {
					var location_302 string = path
					if query != "" {
						location_302 += ("?" + query)
					}
					ctx.Response.Header.Set("Location", location_302)
				},
			)
			return
		}
	}
	defer func() {
		if cache != nil {
			rm.DoneRequest(proxy_url)
		}
	}()

	// 直接重定向到原始 URL
	log.Printf("下载开始：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
	start := time.Now()
	proxy_url, resp, err := fetchWithRedirect(client, proxy_url, 5, config.Headers, *config.HttpTimeout)
	log.Printf("下载结束：%s, %s，%s, 耗时：%s", getClientIP(ctx), tvgID, proxy_url, formatDuration(time.Since(start)))
	if err != nil || resp.StatusCode() != fasthttp.StatusOK {
		ctx.SetBodyString("无法获取内容")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
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
		body, err = modifyMpd(provider.(string), tvgID, proxy_url, resp.Body())
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("xml 重写错误")
			log.Printf("[ERROR] xml 重写错误 %s，%s, %s", tvgID, proxy_url, err)
			return
		}
		if *config.ToFmp4OverHls {
			_, hls_list, _ := DashToHLS(proxy_url, body, tvgID)
			hlsByTvgId.Store(tvgID, hls_list)
			body = []byte(hls_list["master.m3u8"])
			contentType = "application/vnd.apple.mpegurl"
		}

		if strings.Contains(query, "debug") {
			contentType = "text/plain; charset=utf-8"
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	} else if proxy_type == "m3u8" {
		body = modifyHLS(body, tvgID, proxy_url, *config.BestQuality)
		if strings.Contains(query, "debug") {
			contentType = "text/plain; charset=utf-8"
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	} else if proxy_type == "init-m4s" {
		body, err = removePsshAndSinfFromBody(body)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("移除 DRM 信息失败")
			log.Printf("[ERROR] 移除 DRM 信息失败， %s，%s, %s", tvgID, proxy_url, err)
			return
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	} else if proxy_type == "m4s" {
		body, err = fetchAndDecrypt(client, configsByProvider[provider.(string)], tvgID, body, ctx)
		if err != nil {
			return
		}
		if cache != nil {
			cache.Set(proxyURL, body, MyMetadata{"application/octet-stream", tvgID, 0})
		}
	}
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.SetStatusCode(fasthttp.StatusOK)
	log.Printf("解密结束: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, formatDuration(time.Since(start)), formatSize(int64(len(body))))
	resposneBody(ctx, body, contentType)
	log.Printf("代理结束: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, formatDuration(time.Since(start)), formatSize(int64(len(body))))
}

func startAutoGC(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		for range ticker.C {
			runtime.GC()
			debug.FreeOSMemory()
		}
	}()
}

// WaitOrRedirect 等待已有请求完成，最多 waitMax 时间，每 interval 检查一次缓存。
// cacheGetter 用于检查缓存是否可用（返回 data != nil 表示有数据）。
// onHit 用于在命中缓存时输出响应。
func WaitOrRedirect(
	ctx *fasthttp.RequestCtx,
	key string,
	waitCh chan struct{},
	waitMax time.Duration,
	interval time.Duration,
	cacheGetter func(string) ([]byte, string, bool),
	onHit func(*fasthttp.RequestCtx, []byte, string),
	onTimeout func(),
) {
	timeout := time.After(waitMax)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// 周期性检查缓存
			if data, dataType, ok := cacheGetter(key); ok && data != nil {
				ctx.Response.Header.Set("IDRM-CACHE", "HIT")
				onHit(ctx, data, dataType)
				return
			}
		case <-waitCh:
			// 收到完成信号，重新查缓存
			if data, dataType, ok := cacheGetter(key); ok && data != nil {
				ctx.Response.Header.Set("IDRM-CACHE", "HIT")
				onHit(ctx, data, dataType)
				return
			}
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.Response.Header.Set("Retry-After", "1")
			ctx.SetBodyString("资源下载失败，请过一会再试")
			log.Printf("[ERROR] 资源请求失败：%s,%s", getClientIP(ctx), key)
			return
		case <-timeout:
			ctx.SetStatusCode(302)
			ctx.SetBodyString("资源正在下载中，请过一会再试")
			log.Printf("[ERROR]资源正在下载中：%s,%s", getClientIP(ctx), key)
			onTimeout()
			return
		}
	}
}
