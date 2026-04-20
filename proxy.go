package main

import (
	"bytes"
	"context"
	"crypto/md5"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"idrm/utils"
	"io"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/beevik/etree"
	"github.com/patrickmn/go-cache"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/proxy"
)

//go:embed dist
var distFS embed.FS

// 注意: StreamConfig 已移至 config.go

// ---------- 支持多次传参的 flag ----------
type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ", ")
}
func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

// 全局变量
var (
	PUBLISH_ADDRESS            string
	BIND_ADDRESS               string
	CACHE_DIR                  string       // 缓存目录，由命令行参数设置
	PROVIDER_BY_TVG_ID         = sync.Map{} // map[tvgID]providerName
	CONFIGS_BY_PROVIDER        = make(map[string]*StreamConfig)
	configsMu                  sync.RWMutex // 保护 CONFIGS_BY_PROVIDER 的读写锁
	CLIENTS_BY_PROVIDER        = make(map[string]*http.Client)
	M3U_CLIENT_BY_PROVIDER     = make(map[string]*http.Client)
	MANIFEST_CACHE_BY_PROVIDER = make(map[string]*MyCache)
	SEGMENT_CACHE_BY_PROVIDER  = make(map[string]*MyCache)
	HLS_BY_TVG_ID              = sync.Map{}
	RAW_URL_BY_TVG_ID          = sync.Map{}
	HLS_TYPE_BY_TVG_ID         = sync.Map{}
	SINF_BOX_BY_STREAM_ID      = sync.Map{}
	CACHE_302_REDIRECT_URL     = cache.New(60*time.Second, 30*time.Second)
	VISIT_TRACKER              = NewVisitTracker()
)

var version = "1.0.0.33"

// newHTTPClient 创建支持 SOCKS5 或 HTTP 代理的 net/http Client
func newHTTPClient(proxyURL string, timeout int) *http.Client {
	transport := &http.Transport{}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err != nil {
			log.Fatalf("无法解析代理地址: %v", err)
		}

		switch u.Scheme {
		case "socks5", "socks5h":
			// SOCKS5 代理
			var auth *proxy.Auth
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

			transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := dialer.Dial(network, addr)
				if err != nil {
					return nil, err
				}
				conn.SetDeadline(time.Now().Add(30 * time.Second))
				return conn, nil
			}

		case "http", "https":
			// HTTP/HTTPS 代理
			transport.Proxy = http.ProxyURL(u)

		default:
			log.Fatalf("不支持的代理协议: %s", u.Scheme)
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
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
	var (
		cacheDir    string
		enablePprof bool
		pprofAddr   string
	)

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	// 只保留 -l 参数设置监听地址，其他 Provider 相关参数均忽略
	flag.StringVar(&BIND_ADDRESS, "listen", "127.0.0.1:1234", "代理服务器监听端口")
	flag.StringVar(&BIND_ADDRESS, "l", "127.0.0.1:1234", "代理服务器监听端口 (简写)")
	flag.StringVar(&cacheDir, "cache-dir", "./", "cache 文件的保存路径，默认当前路径")
	flag.BoolVar(&enablePprof, "pprof-enable", false, "Enable pprof HTTP server")
	flag.StringVar(&pprofAddr, "pprof-addr", "localhost:7070", "pprof listen address")

	flag.Parse()

	BIND_ADDRESS = strings.TrimSpace(BIND_ADDRESS)

	// 处理监听地址
	if !strings.Contains(BIND_ADDRESS, ":") {
		BIND_ADDRESS = "127.0.0.1:" + BIND_ADDRESS
	} else if strings.HasPrefix(BIND_ADDRESS, ":") {
		BIND_ADDRESS = "127.0.0.1" + BIND_ADDRESS
	}

	// 处理缓存目录
	if !strings.HasSuffix(cacheDir, "/") {
		cacheDir += "/"
	}
	// 设置全局缓存目录（供后续 API 创建的 Provider 使用）
	CACHE_DIR = cacheDir

	// 初始化 API
	initAPI()

	// 启动 pprof 服务（如果启用）
	if enablePprof {
		go func() {
			log.Printf("Starting pprof server on %s", pprofAddr)
			if err := http.ListenAndServe(pprofAddr, nil); err != nil {
				log.Fatalf("pprof server error: %v", err)
			}
		}()
	}

	log.Printf("代理服务器启动在：%s, 当前版本：%s", BIND_ADDRESS, version)
	if err := fasthttp.ListenAndServe(BIND_ADDRESS, requestHandler); err != nil {
		log.Fatalf("ListenAndServe error: %s", err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.URI().PathOriginal())

	switch {
	case strings.HasPrefix(path, "/api/"):
		APIHandler(ctx)
	case strings.HasPrefix(path, "/drm/proxy/"):
		proxyStreamURL(ctx, path)
	case strings.HasSuffix(path, ".m3u"):
		// 验证用户 token 并获取用户
		userToken := string(ctx.QueryArgs().Peek("token"))
		if userToken == "" {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBodyString("Missing token")
			return
		}
		user := getUserByToken(userToken)
		if user == nil {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBodyString("Invalid token")
			return
		}
		loadM3u(ctx, "", userToken)
	case strings.HasPrefix(path, "/stats/cache"):
		CacheStatsHandler(ctx)
	default:
		// 尝试提供静态文件服务
		serveStaticFiles(ctx, path)
	}
}

// serveStaticFiles 提供嵌入的静态文件服务
func serveStaticFiles(ctx *fasthttp.RequestCtx, path string) {
	// 如果路径是根目录，返回 index.html
	if path == "/" || path == "" {
		path = "/index.html"
	}

	// 构建文件路径
	filePath := "dist" + path

	// 尝试读取文件
	content, err := distFS.ReadFile(filePath)
	if err != nil {
		// 文件不存在，返回 index.html（支持前端路由）
		content, err = distFS.ReadFile("dist/index.html")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusNotFound)
			ctx.SetBodyString("Not Found")
			return
		}
		// 返回 index.html
		ctx.SetContentType("text/html; charset=utf-8")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(content)
		return
	}

	// 设置 Content-Type
	contentType := "application/octet-stream"
	switch {
	case strings.HasSuffix(path, ".html"):
		contentType = "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".js"):
		contentType = "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		contentType = "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		contentType = "application/json; charset=utf-8"
	case strings.HasSuffix(path, ".png"):
		contentType = "image/png"
	case strings.HasSuffix(path, ".jpg"), strings.HasSuffix(path, ".jpeg"):
		contentType = "image/jpeg"
	case strings.HasSuffix(path, ".gif"):
		contentType = "image/gif"
	case strings.HasSuffix(path, ".svg"):
		contentType = "image/svg+xml"
	case strings.HasSuffix(path, ".ico"):
		contentType = "image/x-icon"
	case strings.HasSuffix(path, ".woff"):
		contentType = "font/woff"
	case strings.HasSuffix(path, ".woff2"):
		contentType = "font/woff2"
	case strings.HasSuffix(path, ".ttf"):
		contentType = "font/ttf"
	case strings.HasSuffix(path, ".eot"):
		contentType = "application/vnd.ms-fontobject"
	}

	ctx.SetContentType(contentType)
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetBody(content)
}

var reTvg = regexp.MustCompile(`tvg-id="([^"]+)"`)
var reDrm = regexp.MustCompile(`drm_legacy=org\.w3\.clearkey\|([0-9a-fA-F]+):([0-9a-fA-F]+)`)
var reValidTvg = regexp.MustCompile(`^[0-9a-zA-Z_-]+$`)
var reBW = regexp.MustCompile(`BANDWIDTH=(\d+)`)
var reLang = regexp.MustCompile(`LANGUAGE="([^"]+)"`)
var clearKeysMap = sync.Map{} // map[tvgID]clearkey

// handleCustomProviderM3U 处理 custom 类型 Provider 的 M3U 生成
func handleCustomProviderM3U(ctx *fasthttp.RequestCtx, name string, providerID string, userToken string) {
	channelsMu.RLock()
	channels := apiChannels[providerID]
	channelsMu.RUnlock()

	var lines []string
	lines = append(lines, "#EXTM3U")

	// 获取 schema, serverName, port
	var schema = "http"
	var port = "1234"
	var serverName = "127.0.0.1"

	if ctx != nil {
		if h, p, err := net.SplitHostPort(string(ctx.Host())); err == nil {
			port = p
			serverName = h
		} else {
			if string(ctx.URI().Scheme()) == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		schema = GetForwardHeader(ctx, "X-Forwarded-Proto", string(ctx.URI().Scheme()))
		port = GetForwardHeader(ctx, "X-Forwarded-Port", port)
		serverName = strings.Split(GetForwardHeader(ctx, "X-Forwarded-Host", ""), ":")[0]
		if serverName == "" {
			serverName = GetForwardHeader(ctx, "X-Forwarded-Server-Name", serverName)
		}
	} else {
		if PUBLISH_ADDRESS != "" {
			if u, err := url.Parse(PUBLISH_ADDRESS); err == nil {
				schema = u.Scheme
				serverName = u.Hostname()
				port = u.Port()
				if port == "" {
					if schema == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
			}
		} else if BIND_ADDRESS != "" {
			if h, p, err := net.SplitHostPort(BIND_ADDRESS); err == nil {
				serverName = h
				port = p
			}
		}
	}

	prefixAddress := fmt.Sprintf("%s://%s:%s", schema, serverName, port)
	if PUBLISH_ADDRESS != "" {
		prefixAddress = PUBLISH_ADDRESS
	}

	for _, channel := range channels {
		if !channel.Enabled {
			continue
		}

		// 构建 EXTINF 行
		extInf := fmt.Sprintf(`#EXTINF:-1 tvg-id="%s"`, channel.TvgID)
		if channel.GroupTitle != "" {
			extInf += fmt.Sprintf(` group-title="%s"`, channel.GroupTitle)
		}
		if channel.Logo != "" {
			extInf += fmt.Sprintf(` tvg-logo="%s"`, channel.Logo)
		}
		extInf += "," + channel.Name
		lines = append(lines, extInf)

		// 添加 Kodi DRM 配置（如果有）
		if channel.DRM != nil && channel.DRM.Type == "clearkey" {
			drmLine := fmt.Sprintf(`#KODIPROP:inputstream.adaptive.drm_legacy=org.w3.clearkey|%s:%s`,
				channel.DRM.KeyID, channel.DRM.Key)
			lines = append(lines, drmLine)
		}

		// 构建代理 URL
		contentType := "m3u8"
		if strings.Contains(channel.URL, ".mpd") {
			contentType = "mpd"
		}

		var proxyPath string
		configsMu.RLock()
		config := CONFIGS_BY_PROVIDER[name]
		configsMu.RUnlock()
		if config != nil && *(config.ToFmp4OverHls) && contentType == "mpd" {
			proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/%s/index.m3u8", prefixAddress, contentType, channel.TvgID, userToken)
		} else {
			proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/%s/%s", prefixAddress, contentType, channel.TvgID, userToken,
				strings.Replace(channel.URL, "://", "/", 1))
		}
		lines = append(lines, proxyPath)
	}

	result := strings.Join(lines, "\n")
	if ctx != nil {
		ctx.SetContentType("application/vnd.apple.mpegurl")
		ctx.SetBodyString(result)
	}

	log.Printf("Custom Provider %s M3U 已生成，共 %d 个频道", name, len(lines)/2)
}

// 使用示例
// updateProviderStatus 更新 Provider 状态
func updateProviderStatus(providerID string, status string, message string) {
	providersMu.Lock()
	defer providersMu.Unlock()
	if provider, exists := apiProviders[providerID]; exists {
		provider.Status = status
		provider.StatusMessage = message
	}
}

func loadM3u(ctx *fasthttp.RequestCtx, name string, userToken string) {
	if ctx != nil {
		name = getAliasFromPath(string(ctx.URI().Path()))
	}
	// 如果 userToken 为空，尝试从 query 参数获取（用于后台加载）
	if userToken == "" && ctx != nil {
		userToken = string(ctx.QueryArgs().Peek("token"))
	}
	// 验证用户 token（后台加载时 userToken 为空，跳过验证）
	if userToken != "" && ctx != nil {
		user := getUserByToken(userToken)
		if user == nil {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBodyString("Invalid token")
			return
		}
		// 非管理员用户检查是否有权限访问该 Provider
		if user.Role != "admin" {
			// 获取 Provider ID
			pid := getProviderIDByName(name)
			// 检查用户是否有权限访问该 Provider
			hasPermission := false
			for _, allowedID := range user.AllowedProviders {
				if allowedID == pid {
					hasPermission = true
					break
				}
			}
			if !hasPermission {
				ctx.SetStatusCode(fasthttp.StatusForbidden)
				ctx.SetBodyString("No permission to access this provider")
				return
			}
		}
	}
	configsMu.RLock()
	config, ok := CONFIGS_BY_PROVIDER[name]
	configsMu.RUnlock()
	if !ok {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("不存在数据")
		}
		return
	}

	// 获取 Provider ID 和类型
	providerID := getProviderIDByName(name)
	providerType := ""
	providersMu.RLock()
	if provider, exists := apiProviders[providerID]; exists {
		providerType = provider.Type
	}
	providersMu.RUnlock()

	// 如果是 custom 类型，直接从 apiChannels 生成 M3U
	if providerType == "custom" {
		handleCustomProviderM3U(ctx, name, providerID, userToken)
		return
	}

	log.Printf("开始加载M3u: %s, %s, User-Agent:%s", name, config.URL, *config.UserAgent)
	var count = 0
	var body []byte

	// 清空旧频道数据
	if providerID != "" {
		channelsMu.Lock()
		delete(apiChannels, providerID)
		apiChannels[providerID] = make(map[string]*Channel)
		channelsMu.Unlock()
	}

	if strings.HasPrefix(config.URL, "http") {
		statusCode, resonseBody, err, _, _ := HttpGet(M3U_CLIENT_BY_PROVIDER[name], config.URL, []string{"user-agent: " + *config.M3uUserAgent})
		if err != nil {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
				ctx.SetBodyString("无法获取 M3U")
			}
			errorMsg := fmt.Sprintf("无法获取 M3U: %v", err)
			if statusCode > 0 {
				errorMsg = fmt.Sprintf("无法获取 M3U: HTTP %d", statusCode)
			}
			log.Printf("[ERROR]%s: %s, %s", errorMsg, name, config.URL)
			updateProviderStatus(providerID, "error", errorMsg)
			return
		}
		body = resonseBody
	} else if config.URL != "" {
		// 本地文件
		f, err := os.ReadFile(config.URL)
		if err != nil {
			if ctx != nil {
				ctx.SetStatusCode(fasthttp.StatusBadGateway)
				ctx.SetBodyString("无法读取本地 M3U")
			}
			errorMsg := fmt.Sprintf("无法读取本地 M3U: %v", err)
			log.Printf("[ERROR]%s: %s, %s", errorMsg, name, config.URL)
			updateProviderStatus(providerID, "error", errorMsg)
			return
		}
		body = f
	} else {
		// 空 URL，返回空 M3U
		if ctx != nil {
			ctx.SetContentType("application/vnd.apple.mpegurl")
			ctx.SetBodyString("#EXTM3U\n")
		}
		return
	}
	lines := strings.Split(string(body), "\n")
	if len(lines) > 0 && !strings.HasPrefix(lines[0], "#EXT") {
		if ctx != nil {
			ctx.SetStatusCode(fasthttp.StatusBadGateway)
			ctx.SetBodyString("非法的M3U内容")
		}
		errorMsg := "非法的M3U内容"
		log.Printf("[ERROR]%s: %s, %s", errorMsg, name, config.URL)
		if len(body) > 500 {
			log.Printf("[ERROR] 非法M3U内容过长: %s, 前500字符: %s", name, string(body[:500]))
		} else {
			log.Printf("[ERROR] 非法M3U内容: %s, %s", name, string(body))
		}
		updateProviderStatus(providerID, "error", errorMsg)
		return
	}
	base, _ := url.Parse(config.URL)

	var tvgID, clearkey string
	var channelName, groupTitle, logo string
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
	var schema = "http"
	var port = "1234"
	var serverName = "127.0.0.1"
	if ctx != nil {
		schema = GetForwardHeader(ctx, "X-Forwarded-Proto", string(ctx.URI().Scheme()))
		port = GetForwardHeader(ctx, "X-Forwarded-Port", _port)
		serverName = strings.Split(GetForwardHeader(ctx, "X-Forwarded-Host", ""), ":")[0]
		if serverName == "" {
			serverName = GetForwardHeader(ctx, "X-Forwarded-Server-Name", _host)
		}
	} else {
		// 后台加载时使用 PUBLISH_ADDRESS 或 BIND_ADDRESS
		if PUBLISH_ADDRESS != "" {
			// 解析 PUBLISH_ADDRESS
			if u, err := url.Parse(PUBLISH_ADDRESS); err == nil {
				schema = u.Scheme
				serverName = u.Hostname()
				port = u.Port()
				if port == "" {
					if schema == "https" {
						port = "443"
					} else {
						port = "80"
					}
				}
			}
		} else if BIND_ADDRESS != "" {
			// 解析 BIND_ADDRESS
			if h, p, err := net.SplitHostPort(BIND_ADDRESS); err == nil {
				serverName = h
				port = p
			}
		}
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "#EXTM3U" {
			continue
		}

		//兼容台标或者其他标签
		if strings.HasPrefix(line, "#EXTM3U") {
			newLines = append(newLines, line)
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
			// 提取频道名称（逗号后面）
			if idx := strings.LastIndex(line, ","); idx != -1 {
				channelName = strings.TrimSpace(line[idx+1:])
			}
			// 提取 group-title
			if matches := regexp.MustCompile(`group-title="([^"]+)"`).FindStringSubmatch(line); len(matches) == 2 {
				groupTitle = matches[1]
			}
			// 提取 tvg-logo
			if matches := regexp.MustCompile(`tvg-logo="([^"]+)"`).FindStringSubmatch(line); len(matches) == 2 {
				logo = matches[1]
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
			PROVIDER_BY_TVG_ID.Store(tvgID, name)

			prefixAddress := fmt.Sprintf("%s://%s:%s", schema, serverName, port)
			if PUBLISH_ADDRESS != "" {
				prefixAddress = PUBLISH_ADDRESS
			}
			var proxyPath = ""
			configsMu.RLock()
			toFmp4OverHls := *CONFIGS_BY_PROVIDER[name].ToFmp4OverHls
			configsMu.RUnlock()
			if toFmp4OverHls && content_type == "mpd" {
				var suffix = ""
				if strings.Contains(suffix, ".m3u8") {
					suffix = ".m3u8"
				}
				if strings.Contains(suffix, ".mpd") {
					suffix = ".mpd"
				}
				if toFmp4OverHls {
					suffix = ".m3u8"
				}
				proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/%s/index%s",
					prefixAddress,
					content_type,
					tvgID,
					userToken,
					suffix,
				)
			} else {
				proxyPath = fmt.Sprintf("%s/drm/proxy/%s/%s/%s/%s",
					prefixAddress,
					content_type,
					tvgID,
					userToken,
					strings.Replace(u.String(), "://", "/", 1))
			}
			RAW_URL_BY_TVG_ID.Store(tvgID, u.String())
			newLines = append(newLines, proxyPath)
			count = count + 1

			// 将频道信息存储到 apiChannels
			if providerID != "" {
				channel := &Channel{
					ID:         generateID(),
					Name:       channelName,
					TvgID:      tvgID,
					GroupTitle: groupTitle,
					Logo:       logo,
					URL:        u.String(), // 保存原始 URL，不是代理 URL
					Enabled:    true,
				}
				// 如果有 DRM 信息，解析并保存
				if clearkey != "" {
					parts := strings.SplitN(clearkey, ":", 2)
					if len(parts) == 2 {
						channel.DRM = &DRMInfo{
							Type:  "clearkey",
							KeyID: parts[0],
							Key:   parts[1],
						}
					}
				}
				channelsMu.Lock()
				if apiChannels[providerID] == nil {
					apiChannels[providerID] = make(map[string]*Channel)
				}
				apiChannels[providerID][channel.ID] = channel
				channelsMu.Unlock()
			}

			// 重置频道相关变量，准备处理下一个频道
			tvgID = "unknown"
			clearkey = ""
			channelName = ""
			groupTitle = ""
			logo = ""
		}
	}
	var extra = ""
	if PUBLISH_ADDRESS != "" {
		extra += fmt.Sprintf(", 发布地址: %s/%s.m3u", PUBLISH_ADDRESS, name)
	}
	log.Printf("结束加载M3u: %s, 一共%d个频道, 访问地址: http://%s/%s.m3u%s", name, count, BIND_ADDRESS, name, extra)

	// 更新 Provider 的频道数量
	updateProviderChannelCount(name, count)

	// 清除 Provider 的错误状态
	updateProviderStatus(providerID, "ok", "")

	// 保存频道数据到文件
	if providerID != "" {
		saveChannels()
	}

	if ctx != nil {
		ctx.SetStatusCode(fasthttp.StatusOK)
		resposneBody(ctx, []byte(strings.Join(newLines, "\n")), "text/plain; charset=utf-8")
	}
}

var M3U8_INIT_REGEXP = regexp.MustCompile(`URI="([^"]+)"`)
var M3U8_IV_REGEXP = regexp.MustCompile(`IV=0x([0-9A-Fa-f]+)`)

func convert_to_proxy_url(proxy_type string, tvgID string, targetUrl string, baseUrl string, stream_uuid string, userToken string) string {
	url := resolveURL(targetUrl, baseUrl)
	// 如果 userToken 为空，使用 "__idrm_user_token__" 作为占位符，避免 URL 中出现双斜杠
	if userToken == "" {
		userToken = "x__idrm_user_token__x"
	}
	if stream_uuid != "" {
		return fmt.Sprintf("/drm/proxy/%s/%s/%s/%s/%s", proxy_type, tvgID, userToken, stream_uuid, strings.Replace(url, "://", "/", 1))
	}
	return fmt.Sprintf("/drm/proxy/%s/%s/%s/%s", proxy_type, tvgID, userToken, strings.Replace(url, "://", "/", 1))
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
					case "SUBTITLES":
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
		for _, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-MEDIA:") &&
				strings.Contains(line, "TYPE=AUDIO") &&
				strings.Contains(line, fmt.Sprintf("GROUP-ID=\"%s\"", bestAudioGroup)) {

				// 带宽
				var bw int64
				if m := reBW.FindStringSubmatch(line); len(m) == 2 {
					if v, err := strconv.ParseInt(m[1], 10, 64); err == nil {
						bw = v
					}
				}

				// 语言
				lang := ""
				if m := reLang.FindStringSubmatch(line); len(m) == 2 {
					lang = strings.ToLower(m[1])
				}

				// 选择逻辑：先比带宽，再比语言
				if bw > maxABW {
					maxABW = bw
					bestAudioLine = line
				} else if bw == maxABW {
					// 相同码率 → 英文优先
					if strings.HasPrefix(lang, "en") {
						bestAudioLine = line
					}
				}
			}
		}
	}

	// 找对应的字幕
	var ccLines []string
	if bestCCGroup != "" && bestCCGroup != "NONE" {
		for _, line := range lines {
			if strings.HasPrefix(line, "#EXT-X-MEDIA:") &&
				(strings.Contains(line, "TYPE=CLOSED-CAPTIONS") || strings.Contains(line, "TYPE=SUBTITLES")) &&
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

// parseIV 从 #EXT-X-KEY 行解析 IV，返回 []byte
func parseIV(line string) ([]byte, error) {
	matches := M3U8_IV_REGEXP.FindStringSubmatch(line)
	if len(matches) < 2 {
		return nil, fmt.Errorf("IV not found in line: %s", line)
	}

	hexStr := matches[1]

	// 转成字节数组
	iv, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid IV hex: %v", err)
	}

	// 确保长度为 16 字节
	if len(iv) != 16 {
		return nil, fmt.Errorf("IV length must be 16 bytes, got %d", len(iv))
	}

	return iv, nil
}

func modifyHLS(body []byte, tvgID, url string, bestQuality bool, userToken string, convertToProxy ...bool) []byte {
	// 默认转换为代理地址
	doConvert := true
	if len(convertToProxy) > 0 {
		doConvert = convertToProxy[0]
	}
	strBody := string(body)

	// 如果启用最高画质过滤
	if bestQuality && strings.Contains(strBody, "#EXT-X-STREAM-INF:") {
		strBody = filterHighestAV(strBody)
	}

	lines := strings.Split(strBody, "\n")
	var newLines []string
	var lastLineWasExtInf bool
	var lastLineWasExtStremInf bool

	hash := md5.Sum([]byte(url))
	stream_uuid := hex.EncodeToString(hash[:])
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#EXT-X-DATERANGE") {
			continue
		}

		// 跳过 KEY（你这里是直接忽略的）
		if strings.HasPrefix(line, "#EXT-X-KEY:METHOD=") {
			if _, exists := SINF_BOX_BY_STREAM_ID.Load(stream_uuid); !exists {
				if iv, err := parseIV(line); err == nil && len(iv) > 0 {
					sinBox := new(mp4.SinfBox)
					sinBox.Schm = new(mp4.SchmBox)
					sinBox.Schi = new(mp4.SchiBox)
					sinBox.Schi.Tenc = new(mp4.TencBox)

					sinBox.Schm.SchemeType = "cbcs"
					SINF_BOX_BY_STREAM_ID.Store(stream_uuid, sinBox)
					sinBox.Schi.Tenc.DefaultConstantIV = iv
				}
			}
			continue
		}

		// 替换 init-m4s (EXT-X-MAP)
		if strings.HasPrefix(line, "#EXT-X-MAP:") {
			matches := M3U8_INIT_REGEXP.FindStringSubmatch(line)
			if len(matches) == 2 {
				var newURI string
				if doConvert {
					newURI = convert_to_proxy_url("init-m4s", tvgID, matches[1], url, stream_uuid, userToken)
				} else {
					newURI = resolveURL(matches[1], url)
				}
				line = M3U8_INIT_REGEXP.ReplaceAllString(line, `URI="`+newURI+`"`)
			}
		}

		// 如果上一行是 EXTINF → 当前行是分片地址
		if lastLineWasExtInf && !strings.HasPrefix(line, "#") {
			if doConvert {
				media_type := "m4s"
				if strings.Contains(line, ".ts") {
					media_type = "ts"
				}
				line = convert_to_proxy_url(media_type, tvgID, line, url, stream_uuid, userToken)
			} else {
				line = resolveURL(line, url)
			}
			lastLineWasExtInf = false
		}

		if strings.HasPrefix(line, "#EXTINF") {
			lastLineWasExtInf = true
		}

		if strings.HasPrefix(line, "#EXT-X-STREAM-INF") {
			lastLineWasExtStremInf = true
		}

		// 替换 #EXT-X-MEDIA
		if strings.HasPrefix(line, "#EXT-X-MEDIA:") {
			matches := M3U8_INIT_REGEXP.FindStringSubmatch(line)
			if len(matches) == 2 {
				var newURI string
				if doConvert {
					newURI = convert_to_proxy_url("m3u8", tvgID, matches[1], url, "", userToken)
				} else {
					newURI = resolveURL(matches[1], url)
				}
				line = M3U8_INIT_REGEXP.ReplaceAllString(line, `URI="`+newURI+`"`)
			}
		}

		//替换m3u8
		if lastLineWasExtStremInf && !strings.HasPrefix(line, "http") && !strings.HasPrefix(line, "#") && strings.Contains(line, ".m3u8") {
			if doConvert {
				line = convert_to_proxy_url("m3u8", tvgID, line, url, "", userToken)
			} else {
				line = resolveURL(line, url)
			}
			lastLineWasExtStremInf = false
		}
		newLines = append(newLines, line)
	}

	return []byte(strings.Join(newLines, "\n"))
}

// parseISO8601ToSeconds 将 PT1H2M3S 格式转换为秒数
func parseISO8601ToSeconds(duration string) float64 {
	re := regexp.MustCompile(`PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?`)
	matches := re.FindStringSubmatch(duration)
	if matches == nil {
		return 0
	}

	var total float64
	if matches[1] != "" { // 小时
		val, _ := strconv.ParseFloat(matches[1], 64)
		total += val * 3600
	}
	if matches[2] != "" { // 分钟
		val, _ := strconv.ParseFloat(matches[2], 64)
		total += val * 60
	}
	if matches[3] != "" { // 秒
		val, _ := strconv.ParseFloat(matches[3], 64)
		total += val
	}
	return total
}

func modifyMpd(provider string, tvgId string, url string, body []byte, userToken string) ([]byte, error) {
	doc := etree.NewDocument()
	doc.ReadFromBytes(body)

	mpd := doc.FindElement("//MPD")
	if mpd != nil {
		// 删除 DRM 命名空间
		mpd.RemoveAttr("xmlns:cenc")
		mpd.RemoveAttr("xmlns:mspr")
		// 保留必要的其他命名空间
		// 比如 xmlns, xmlns:xsi, xmlns:scte35
	}

	// 2. 获取所有的 Period
	periods := doc.FindElements("//Period")
	if len(periods) > 1 {
		var keepIndex int
		isStatic := mpd.SelectAttrValue("type", "static") == "static"
		if isStatic {
			// VOD 逻辑：选取 duration 最长的那个
			maxSecs := -1.0
			for i, p := range periods {
				dStr := p.SelectAttrValue("duration", "PT0S")
				secs := parseISO8601ToSeconds(dStr) // 调用下方解析函数
				if secs > maxSecs {
					maxSecs = secs
					keepIndex = i
				}
			}
		} else {
			// 非 static 逻辑（Live）：保留最后一个
			keepIndex = len(periods) - 1
		}

		// 4. 执行删除操作
		for i, p := range periods {
			if i != keepIndex {
				if parent := p.Parent(); parent != nil {
					parent.RemoveChild(p)
				}
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
	stream_index := 0
	for _, st := range segTemplates {
		media := st.SelectAttrValue("media", "")
		if media != "" {
			media = joinBaseAndMedia(collectBaseURLs(st), media)
			media_type := "m4s"
			if strings.Contains(media, "jpg") || strings.Contains(media, "png") {
				media_type = "jpg"
			}
			st.RemoveAttr("media")
			st.CreateAttr("media", convert_to_proxy_url(media_type, tvgId, media, url, strconv.Itoa(stream_index), userToken))
		}

		init := st.SelectAttrValue("initialization", "")
		if init != "" {
			init = joinBaseAndMedia(collectBaseURLs(st), init)
			st.RemoveAttr("initialization")
			st.CreateAttr("initialization", convert_to_proxy_url("init-m4s", tvgId, init, url, strconv.Itoa(stream_index), userToken))
		}
		stream_index++
	}

	//删除BaseURL
	BaseURLs := doc.FindElements("//BaseURL")
	for _, bu := range BaseURLs {
		parent := bu.Parent() // 获取父节点
		if parent != nil {
			parent.RemoveChild(bu) // 从父节点删除自己
		}
	}

	configsMu.RLock()
	bestQuality := *CONFIGS_BY_PROVIDER[provider].BestQuality
	configsMu.RUnlock()
	if bestQuality {
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

// 全局 token 密钥（实际生产环境应该从配置或环境变量读取）
var PROXY_TOKEN_SECRET = "idrm-secret-key-change-in-production"

// generateProxyToken 生成代理 URL 的 token
func generateProxyToken(tvgID string) string {
	// 简单的 token 生成：tvgID + secret 的 MD5
	h := md5.New()
	io.WriteString(h, tvgID+PROXY_TOKEN_SECRET)
	return hex.EncodeToString(h.Sum(nil))[:16] // 取前16位
}

// verifyProxyToken 验证代理 URL 的 token
func verifyProxyToken(tvgID string, token string) bool {
	expectedToken := generateProxyToken(tvgID)
	return token == expectedToken
}

// verifyUserToken 验证用户 token
func verifyUserToken(ctx *fasthttp.RequestCtx) bool {
	token := string(ctx.QueryArgs().Peek("token"))
	if token == "" {
		return false
	}
	// 查找具有该 token 的用户
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, user := range apiUsers {
		if user.Token == token {
			return true
		}
	}
	return false
}

// getUserByToken 根据 token 获取用户
func getUserByToken(token string) *User {
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, user := range apiUsers {
		if user.Token == token {
			return user
		}
	}
	return nil
}

// 代理流 URL
func proxyStreamURL(ctx *fasthttp.RequestCtx, path string) {
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	parts := strings.SplitN(strings.TrimPrefix(path, "/drm/proxy/"), "/", 4)
	if len(parts) < 4 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("Invalid proxy URL")
		return
	}
	query := string(ctx.QueryArgs().QueryString())
	proxy_type := parts[0]
	tvgID := parts[1]
	userToken := parts[2]
	var proxy_url = parts[3]

	// 验证用户 token（空 token 只允许后台预加载场景使用）
	if userToken != "" {
		user := getUserByToken(userToken)
		if user == nil {
			ctx.SetStatusCode(fasthttp.StatusForbidden)
			ctx.SetBodyString("Invalid token")
			return
		}
	}
	var stream_uuid string = "default"
	if proxy_type == "m3u8" || proxy_type == "mpd" {
		if strings.HasPrefix(proxy_url, "index.") {
			raw_url, ok := RAW_URL_BY_TVG_ID.Load(tvgID)
			if !ok {
				ctx.SetStatusCode(fasthttp.StatusBadRequest)
				ctx.SetBodyString("invalid tvg id, not found")
				return
			}
			proxy_url = raw_url.(string)
		}
	} else {
		if proxy_type == "m4s" || proxy_type == "init-m4s" || proxy_type == "ts" {
			stream_uuid = strings.Split(proxy_url, "/")[0]
			proxy_url = strings.Replace(proxy_url, stream_uuid+"/", "", 1)
		}
	}
	proxy_url = strings.Replace(proxy_url, "http/", "http://", 1)
	proxy_url = strings.Replace(proxy_url, "https/", "https://", 1)
	if query != "" {
		proxy_url += "?" + query
	}
	proxy_url = strings.Replace(proxy_url, "?debug", "", 1)
	proxy_url = strings.Replace(proxy_url, "&debug", "", 1)

	log.Printf("代理开始：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)

	provider, ok := PROVIDER_BY_TVG_ID.Load(tvgID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id, not found provider")
		log.Printf("[ERROR] invalid tvg id, %s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
		return
	}

	client, ok := CLIENTS_BY_PROVIDER[provider.(string)]
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		log.Printf("[ERROR] invalid tvg id, %s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
		return
	}

	configsMu.RLock()
	config := CONFIGS_BY_PROVIDER[provider.(string)]
	configsMu.RUnlock()
	raw_url, ok := RAW_URL_BY_TVG_ID.Load(tvgID)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.SetBodyString("invalid tvg id")
		log.Printf("[ERROR] invalid tvg id, %s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
		return
	}

	if *config.SpeedUp || *config.ToFmp4OverHls {
		startOrResetUpdater(provider.(string), tvgID, raw_url.(string), client, config, 2*time.Second)
	}

	if proxy_type == "hls" {
		hls_list, ok := HLS_BY_TVG_ID.Load(tvgID)
		if ok {
			body := []byte(hls_list.(map[string]string)[proxy_url])
			body = []byte(strings.ReplaceAll(string(body), "__idrm_user_token__", userToken))
			contentType := "application/vnd.apple.mpegurl"
			ctx.Response.Header.Set("Cache-Control", "no-cache")
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.SetBody(body)
			if strings.Contains(query, "debug") {
				contentType = "text/plain; charset=utf-8"
			}
			ctx.SetContentType(contentType)
		}
		return
	}

	is_mainfest_cache := true
	cache := MANIFEST_CACHE_BY_PROVIDER[provider.(string)]
	if proxy_type == "m4s" || proxy_type == "ts" {
		VISIT_TRACKER.RecordVisit(tvgID, getClientIP(ctx), userToken, proxy_url, stream_uuid)
		cache = SEGMENT_CACHE_BY_PROVIDER[provider.(string)]
		is_mainfest_cache = false
	}

	if cache != nil {
		data, dataType, _, _ := cache.Get(proxy_url)
		if data != nil {
			log.Printf("资源hit：%s, %s，%s", getClientIP(ctx), tvgID, proxy_url)
			ctx.SetStatusCode(fasthttp.StatusOK)
			ctx.Response.Header.Set("IDRM-CACHE", "HIT")
			if is_mainfest_cache {
				data = []byte(strings.ReplaceAll(string(data), "__idrm_user_token__", userToken))
			}
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
					ctx.SetStatusCode(302)
					ctx.Response.Header.Set("Location", path)
					ctx.SetBodyString("资源正在下载中，请过一会再试")
					log.Printf("[ERROR]资源正在下载中：%s,%s", getClientIP(ctx), proxy_url)
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
	statusCode, responseBody, err, contentType, finalURI := HttpGet(client, proxy_url, config.Headers)
	log.Printf("下载结束：%s, %s，%s, 耗时：%s", getClientIP(ctx), tvgID, proxy_url, utils.FormatDuration(time.Since(start)))
	if err != nil {
		ctx.SetBodyString("无法获取内容")
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			log.Printf("[ERROR] 下载错误：%s，%s, %v", tvgID, proxy_url, err)
		} else {
			ctx.SetStatusCode(statusCode)
			log.Printf("[ERROR] 下载错误：%s，%s, 状态码: %d", tvgID, proxy_url, statusCode)
		}
		return
	}
	body := responseBody
	if proxy_type == "mpd" || contentType == "application/dash+xml" {
		body, err = modifyMpd(provider.(string), tvgID, finalURI, body, userToken)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("xml 重写错误")
			log.Printf("[ERROR] xml 重写错误 %s，%s, %s", tvgID, finalURI, err)
			return
		}
		if *config.ToFmp4OverHls {
			_, hls_list, _ := DashToHLS(finalURI, body, tvgID, *config.BestQuality, userToken)
			HLS_BY_TVG_ID.Store(tvgID, hls_list)
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
		body = modifyHLS(body, tvgID, finalURI, *config.BestQuality, userToken)
		if strings.Contains(query, "debug") {
			contentType = "text/plain; charset=utf-8"
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	} else if proxy_type == "init-m4s" {
		modifiedBody, sinfBox, err := modifyInitM4sFromBody(body)
		if err != nil {
			ctx.SetStatusCode(fasthttp.StatusServiceUnavailable)
			ctx.SetBodyString("移除 DRM 信息失败")
			log.Printf("[ERROR] 移除 DRM 信息失败， %s，%s, %s", tvgID, proxy_url, err)
			return
		}
		SINF_BOX_BY_STREAM_ID.Store(stream_uuid, sinfBox)
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
		body = modifiedBody
	} else if proxy_type == "m4s" {
		var sinfBox *mp4.SinfBox = nil
		if t, ok := SINF_BOX_BY_STREAM_ID.Load(stream_uuid); ok {
			sinfBox = t.(*mp4.SinfBox)
		}
		configsMu.RLock()
		config := CONFIGS_BY_PROVIDER[provider.(string)]
		configsMu.RUnlock()
		body, err = fetchAndDecrypt(client, config, tvgID, body, ctx, sinfBox, proxy_type)
		if err != nil {
			log.Printf("解密m4s错误: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, utils.FormatDuration(time.Since(start)), utils.FormatSize(int64(len(body))))
			return
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	} else if proxy_type == "ts" {
		var sinfBox *mp4.SinfBox = nil
		if t, ok := SINF_BOX_BY_STREAM_ID.Load(stream_uuid); ok {
			sinfBox = t.(*mp4.SinfBox)
		}
		configsMu.RLock()
		config := CONFIGS_BY_PROVIDER[provider.(string)]
		configsMu.RUnlock()
		body, err = fetchAndDecrypt(client, config, tvgID, body, ctx, sinfBox, proxy_type)
		if err != nil {
			log.Printf("解密ts错误: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, utils.FormatDuration(time.Since(start)), utils.FormatSize(int64(len(body))))
			return
		}
		if cache != nil {
			cache.Set(proxy_url, body, MyMetadata{contentType, tvgID, 0})
		}
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	log.Printf("解密结束: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, utils.FormatDuration(time.Since(start)), utils.FormatSize(int64(len(body))))
	resposneBody(ctx, body, contentType)
	log.Printf("代理结束: %s, %s, %s, 耗时：%s, 大小=%s,", getClientIP(ctx), tvgID, proxy_url, utils.FormatDuration(time.Since(start)), utils.FormatSize(int64(len(body))))
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
				if onHit != nil {
					onHit(ctx, data, dataType)
				}
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
			ctx.Response.Header.Set("Retry-After", "2")
			ctx.SetBodyString("资源下载失败，请过一会再试")
			log.Printf("[ERROR] 资源请求失败：%s,%s", getClientIP(ctx), key)
			return
		case <-timeout:
			if onTimeout != nil {
				onTimeout()
			}
			return
		}
	}
}
