package main

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

// User 用户模型（保持兼容，后续迁移到 module/user/entity）
type User struct {
	ID                 string   `json:"id"`
	Username           string   `json:"username"`
	Password           string   `json:"password"`
	Role               string   `json:"role"`
	AllowedProviders   []string `json:"allowedProviders"`
	CreatedAt          string   `json:"createdAt"`
	NeedChangePassword bool     `json:"needChangePassword"`
	Token              string   `json:"token"` // 用于 M3U 和代理访问的 token
}

// ToSafeUser 返回不包含密码的用户信息
func (u *User) ToSafeUser() User {
	return User{
		ID:                 u.ID,
		Username:           u.Username,
		Role:               u.Role,
		AllowedProviders:   u.AllowedProviders,
		CreatedAt:          u.CreatedAt,
		NeedChangePassword: u.NeedChangePassword,
		Token:              u.Token,
	}
}

// Provider 提供商模型
type Provider struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Type          string         `json:"type"` // remote 或 custom
	URL           string         `json:"url"`
	Headers       []string       `json:"headers"`
	StreamHeaders []string       `json:"streamHeaders"`
	Proxy         string         `json:"proxy"`
	StreamProxy   string         `json:"streamProxy"`
	ChannelCount  int            `json:"channelCount"`
	Config        ProviderConfig `json:"config"`
	Status        string         `json:"status"`        // 状态: ok, error
	StatusMessage string         `json:"statusMessage"` // 状态信息/错误信息
	CreatedAt     string         `json:"createdAt"`
}

// ProviderConfig 提供商配置
type ProviderConfig struct {
	BestQuality        bool `json:"bestQuality"`
	SpeedUp            bool `json:"speedUp"`
	ToHls              bool `json:"toHls"`
	CacheManifest      int  `json:"cacheManifest"`
	CacheSegmentFile   int  `json:"cacheSegmentFile"`
	CacheSegmentMemory int  `json:"cacheSegmentMemory"`
}

// Channel 频道模型
type Channel struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	TvgID      string   `json:"tvgId"`
	GroupTitle string   `json:"groupTitle"`
	Logo       string   `json:"logo"`
	URL        string   `json:"url"`
	Enabled    bool     `json:"enabled"`
	DRM        *DRMInfo `json:"drm,omitempty"`
}

// DRMInfo DRM 信息
type DRMInfo struct {
	Type  string `json:"type"`
	Value string `json:"value"` // ClearKey 配置值：可以是 "kid:key" 或 HTTP URL
}

// APIResponse 统一 API 响应格式
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// LoginRequest 登录请求
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录响应
type LoginResponse struct {
	Token              string `json:"token"`
	UserInfo           User   `json:"userInfo"`
	NeedChangePassword bool   `json:"needChangePassword"` // 是否需要修改密码
}

// ChannelListResponse 频道列表响应
type ChannelListResponse struct {
	List         []Channel `json:"list"`
	Total        int       `json:"total"`
	Groups       []string  `json:"groups"`
	ProviderName string    `json:"providerName"`
}

// ---------- 全局变量 ----------

var (
	// 内存数据存储
	apiUsers     = make(map[string]*User)
	apiProviders = make(map[string]*Provider)
	apiChannels  = make(map[string]map[string]*Channel) // providerId -> channelId -> Channel

	// 互斥锁
	usersMu     sync.RWMutex
	providersMu sync.RWMutex
	channelsMu  sync.RWMutex

	// 数据文件路径
	dataDir       = "./idrm-data"
	usersFile     = filepath.Join(dataDir, "users.json")
	providersFile = filepath.Join(dataDir, "providers.json")
	channelsFile  = filepath.Join(dataDir, "channels.json")
)

// ---------- 初始化 ----------

// systemInitialized 标记系统是否已初始化（users.json 是否存在）
var systemInitialized = true

func initAPI() {
	// 创建数据目录
	os.MkdirAll(dataDir, 0755)

	// 检查 users.json 是否存在
	_, err := os.Stat(usersFile)
	if os.IsNotExist(err) {
		// 系统未初始化
		systemInitialized = false
		log.Printf("系统未初始化，首次登录时需要设置管理员密码")
	}

	// 先加载已有数据
	loadAllData()

	// 如果系统已初始化但 admin 用户不存在，创建默认的
	usersMu.Lock()
	if systemInitialized {
		if _, exists := apiUsers["1"]; !exists {
			adminUser := &User{
				ID:                 "1",
				Username:           "admin",
				Password:           "admin", // 默认密码，首次登录后必须修改
				Role:               "admin",
				AllowedProviders:   []string{},
				CreatedAt:          time.Now().Format("2006-01-02 15:04:05"),
				NeedChangePassword: true, // 首次登录需要修改密码
				Token:              generateUserToken(),
			}
			apiUsers[adminUser.ID] = adminUser
			log.Printf("创建默认管理员用户: admin/admin")
		}
	}
	usersMu.Unlock()

	// 同步现有 StreamConfig 到 Provider
	syncStreamConfigsToProviders()

	// 注册所有 Provider 到运行时
	registerAllProvidersRuntime()

	// 保存数据（确保新创建的 admin 被写入文件）
	if systemInitialized {
		saveUsers()
	}
}

// syncStreamConfigsToProviders 将现有的 StreamConfig 同步到 Provider
func syncStreamConfigsToProviders() {
	providersMu.Lock()
	configsMu.RLock()
	configsCopy := make(map[string]*StreamConfig)
	for name, config := range CONFIGS_BY_PROVIDER {
		configsCopy[name] = config
	}
	configsMu.RUnlock()

	for name, config := range configsCopy {
		// 检查是否已存在同名 Provider
		exists := false
		for _, p := range apiProviders {
			if p.Name == name {
				exists = true
				break
			}
		}

		if !exists {
			provider := &Provider{
				ID:            generateID(),
				Name:          name,
				Type:          "remote",
				URL:           config.URL,
				Headers:       []string{},
				StreamHeaders: config.Headers,
				Proxy:         config.Proxy,
				StreamProxy:   config.M3uProxy,
				ChannelCount:  0,
				Config: ProviderConfig{
					BestQuality:        *config.BestQuality,
					SpeedUp:            *config.SpeedUp,
					ToHls:              *config.ToFmp4OverHls,
					CacheManifest:      *config.ManifestCacheExpire,
					CacheSegmentFile:   *config.SegmentFileCacheExpire,
					CacheSegmentMemory: *config.SegmentMemoryCacheExpire,
				},
			}
			apiProviders[provider.ID] = provider

			// 初始化频道存储
			channelsMu.Lock()
			if apiChannels[provider.ID] == nil {
				apiChannels[provider.ID] = make(map[string]*Channel)
			}
			channelsMu.Unlock()

			// 注册到运行时（注意：这里在 providersMu 内，registerProviderRuntime 会访问 CONFIGS_BY_PROVIDER 等全局变量）
			// CONFIGS_BY_PROVIDER 已经在 proxy.go 的 main 函数中设置，这里不需要重复注册
		}
	}
	providersMu.Unlock()

	saveProviders()
	saveChannels()
}

// ---------- 数据持久化 ----------

func loadAllData() {
	loadUsers()
	loadProviders()
	loadChannels()
	importLegacyConfig()
}

func loadUsers() {
	data, err := os.ReadFile(usersFile)
	if err != nil {
		return
	}
	var loadedUsers map[string]*User
	if err := json.Unmarshal(data, &loadedUsers); err != nil {
		log.Printf("加载用户数据失败: %v", err)
		return
	}

	usersMu.Lock()
	needSave := false
	for id, user := range loadedUsers {
		// 为没有 token 的旧用户生成 token
		if user.Token == "" {
			user.Token = generateUserToken()
			log.Printf("为用户 %s 生成访问 token", user.Username)
			needSave = true
		}
		apiUsers[id] = user
	}
	usersMu.Unlock()
	log.Printf("已加载 %d 个用户", len(apiUsers))
	// 如果有用户生成了新 token，保存到文件
	if needSave {
		saveUsers()
	}
}

func saveUsers() {
	usersMu.RLock()
	data, err := json.MarshalIndent(apiUsers, "", "  ")
	usersMu.RUnlock()

	if err != nil {
		log.Printf("保存用户数据失败: %v", err)
		return
	}

	if err := os.WriteFile(usersFile, data, 0644); err != nil {
		log.Printf("写入用户数据失败: %v", err)
	} else {
		log.Printf("用户数据已保存到: %s", usersFile)
	}
}

func loadProviders() {
	data, err := os.ReadFile(providersFile)
	if err != nil {
		return
	}
	var loadedProviders map[string]*Provider
	if err := json.Unmarshal(data, &loadedProviders); err != nil {
		log.Printf("加载 Provider 数据失败: %v", err)
		return
	}

	providersMu.Lock()
	defer providersMu.Unlock()
	apiProviders = loadedProviders
}

func saveProviders() {
	providersMu.RLock()
	data, err := json.MarshalIndent(apiProviders, "", "  ")
	providersMu.RUnlock()

	if err != nil {
		log.Printf("保存 Provider 数据失败: %v", err)
		return
	}

	if err := os.WriteFile(providersFile, data, 0644); err != nil {
		log.Printf("写入 Provider 数据失败: %v", err)
	}
}

func loadChannels() {
	data, err := os.ReadFile(channelsFile)
	if err != nil {
		return
	}
	var loadedChannels map[string]map[string]*Channel
	if err := json.Unmarshal(data, &loadedChannels); err != nil {
		log.Printf("加载频道数据失败: %v", err)
		return
	}

	channelsMu.Lock()
	defer channelsMu.Unlock()
	apiChannels = loadedChannels

	// 注册 custom 类型 Provider 的频道 TVG ID 到全局映射
	for providerID, channels := range loadedChannels {
		provider := apiProviders[providerID]
		if provider == nil || provider.Type != "custom" {
			continue
		}
		for _, channel := range channels {
			if channel.TvgID != "" && channel.URL != "" {
				PROVIDER_BY_TVG_ID.Store(channel.TvgID, provider.Name)
				RAW_URL_BY_TVG_ID.Store(channel.TvgID, channel.URL)
				
				// 如果有 DRM 配置，同步更新 clearKeysMap
				if channel.DRM != nil && channel.DRM.Type == "clearkey" && channel.DRM.Value != "" {
					clearKeysMap.Store(channel.TvgID, channel.DRM.Value)
				}
			}
		}
	}
}

// LegacyProvider 旧版配置格式
type LegacyProvider struct {
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Proxy       string   `json:"proxy"`
	Headers     []string `json:"headers"`
	BestQuality bool     `json:"best-quality"`
	SpeedUp     bool     `json:"speed-up"`
	ToHls       bool     `json:"to-hls"`
}

// importLegacyConfig 从程序当前目录的 idrm.json 导入旧版配置
func importLegacyConfig() {
	// 从程序当前目录读取
	legacyFile := "idrm.json"
	log.Printf("检查旧版配置文件: %s", legacyFile)

	data, err := os.ReadFile(legacyFile)
	if err != nil {
		// 文件不存在，直接返回
		log.Printf("旧版配置文件不存在或无法读取: %v", err)
		return
	}

	log.Printf("读取到旧版配置文件，大小: %d 字节", len(data))

	var legacyProviders []LegacyProvider
	if err := json.Unmarshal(data, &legacyProviders); err != nil {
		log.Printf("解析旧版配置文件失败: %v", err)
		return
	}

	providersMu.Lock()
	defer providersMu.Unlock()

	importedCount := 0
	for _, legacy := range legacyProviders {
		// 检查是否已存在同名 Provider
		exists := false
		for _, p := range apiProviders {
			if p.Name == legacy.Name {
				exists = true
				break
			}
		}

		if exists {
			log.Printf("Provider %s 已存在，跳过导入", legacy.Name)
			continue
		}

		// 创建新 Provider
		// idrm.json 中的 proxy 是 stream proxy（流媒体代理），不是 m3u 代理
		provider := &Provider{
			ID:            generateID(),
			Name:          legacy.Name,
			Type:          "remote",
			URL:           legacy.URL,
			Headers:       legacy.Headers,
			StreamHeaders: legacy.Headers,
			Proxy:         "",           // m3u 代理为空
			StreamProxy:   legacy.Proxy, // stream proxy
			ChannelCount:  0,
			Config: ProviderConfig{
				BestQuality:        legacy.BestQuality,
				SpeedUp:            legacy.SpeedUp,
				ToHls:              legacy.ToHls,
				CacheManifest:      -1,
				CacheSegmentFile:   -1,
				CacheSegmentMemory: -1,
			},
			CreatedAt: time.Now().Format("2006-01-02 15:04:05"),
		}

		apiProviders[provider.ID] = provider
		importedCount++
		log.Printf("已从旧版配置导入 Provider: %s", legacy.Name)
	}

	if importedCount > 0 {
		log.Printf("成功导入 %d 个 Provider 从旧版配置", importedCount)
		// 保存到新的数据文件
		go saveProviders()

		// 重命名旧配置文件，防止重复导入
		oldFile := legacyFile + ".old"
		if err := os.Rename(legacyFile, oldFile); err == nil {
			log.Printf("旧配置文件已重命名为: %s", oldFile)
		}
	}
}

func saveChannels() {
	channelsMu.RLock()
	data, err := json.MarshalIndent(apiChannels, "", "  ")
	channelsMu.RUnlock()

	if err != nil {
		log.Printf("保存频道数据失败: %v", err)
		return
	}

	if err := os.WriteFile(channelsFile, data, 0644); err != nil {
		log.Printf("写入频道数据失败: %v", err)
	}
}

// ---------- Provider 运行时管理 ----------

// registerAllProvidersRuntime 注册所有 Provider 到运行时（启动时调用）
func registerAllProvidersRuntime() {
	providersMu.RLock()
	defer providersMu.RUnlock()

	// 先收集需要异步加载 M3U 的 Provider 名称
	var remoteProviders []string
	for _, provider := range apiProviders {
		registerProviderRuntime(provider)

		// 收集需要异步加载 M3U 的 Provider
		if provider.Type == "remote" && provider.URL != "" {
			remoteProviders = append(remoteProviders, provider.Name)
		}
	}
	log.Printf("已注册 %d 个 Provider 到运行时", len(apiProviders))

	// 所有 Provider 注册完成后再启动异步加载 M3U，避免并发读写 map
	for _, name := range remoteProviders {
		go func(n string) {
			loadM3u(nil, n, "")
		}(name)
	}
}

// registerProviderRuntime 注册 Provider 到运行时（创建 HTTP 客户端、缓存等）
func registerProviderRuntime(provider *Provider) {
	// 转换为 StreamConfig
	config := &StreamConfig{
		Name:                     provider.Name,
		URL:                      provider.URL,
		Headers:                  provider.Headers,
		Proxy:                    provider.Proxy,
		M3uProxy:                 provider.StreamProxy,
		BestQuality:              &provider.Config.BestQuality,
		ToFmp4OverHls:            &provider.Config.ToHls,
		SpeedUp:                  &provider.Config.SpeedUp,
		HttpTimeout:              &provider.Config.CacheManifest,
		ManifestCacheExpire:      &provider.Config.CacheManifest,
		SegmentMemoryCacheExpire: &provider.Config.CacheSegmentMemory,
		SegmentFileCacheExpire:   &provider.Config.CacheSegmentFile,
	}

	// 处理 User-Agent
	ua := "okhttp/4.12.0"
	for _, h := range provider.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			if key == "user-agent" {
				ua = value
				break
			}
		}
	}
	config.UserAgent = &ua
	config.M3uUserAgent = &ua

	// 注册到全局变量
	configsMu.Lock()
	CONFIGS_BY_PROVIDER[provider.Name] = config
	configsMu.Unlock()
	// CLIENTS_BY_PROVIDER 用于流媒体请求，使用 M3uProxy（流媒体代理）
	CLIENTS_BY_PROVIDER[provider.Name] = newHTTPClient(config.M3uProxy, 30)
	// M3U_CLIENT_BY_PROVIDER 用于获取 M3U 文件，使用 Proxy（M3U 代理）
	M3U_CLIENT_BY_PROVIDER[provider.Name] = newHTTPClient(config.Proxy, 30)

	// 创建缓存
	if *config.ManifestCacheExpire >= 0 {
		cacheDir := "./"
		MANIFEST_CACHE_BY_PROVIDER[provider.Name] = NewMyCache(cacheDir+"idrm-cache/"+provider.Name+"/manifest", *config.ManifestCacheExpire, -1)
	}

	if *config.SegmentFileCacheExpire >= 0 || *config.SegmentMemoryCacheExpire >= 0 || *config.SpeedUp {
		if *config.SegmentMemoryCacheExpire < 10 {
			*config.SegmentMemoryCacheExpire = 10
		}
		cacheDir := "./"
		SEGMENT_CACHE_BY_PROVIDER[provider.Name] = NewMyCache(cacheDir+"idrm-cache/"+provider.Name, *config.SegmentMemoryCacheExpire, *config.SegmentFileCacheExpire)
	}

	log.Printf("Provider %s 已注册到运行时", provider.Name)
}

// unregisterProviderRuntime 从运行时注销 Provider
func unregisterProviderRuntime(providerName string) {
	configsMu.Lock()
	delete(CONFIGS_BY_PROVIDER, providerName)
	configsMu.Unlock()

	// 关闭 HTTP Client 连接池，释放资源
	if client, ok := CLIENTS_BY_PROVIDER[providerName]; ok && client != nil {
		client.CloseIdleConnections()
	}
	if m3uClient, ok := M3U_CLIENT_BY_PROVIDER[providerName]; ok && m3uClient != nil {
		m3uClient.CloseIdleConnections()
	}

	delete(CLIENTS_BY_PROVIDER, providerName)
	delete(M3U_CLIENT_BY_PROVIDER, providerName)
	delete(MANIFEST_CACHE_BY_PROVIDER, providerName)
	delete(SEGMENT_CACHE_BY_PROVIDER, providerName)
	log.Printf("Provider %s 已从运行时注销", providerName)
}

// updateProviderChannelCount 更新 Provider 的频道数量
func updateProviderChannelCount(providerName string, count int) {
	providersMu.Lock()
	defer providersMu.Unlock()

	for _, provider := range apiProviders {
		if provider.Name == providerName {
			provider.ChannelCount = count
			log.Printf("Provider %s 频道数量已更新为 %d", providerName, count)
			// 异步保存到文件
			go saveProviders()
			return
		}
	}
}

// getProviderIDByName 根据名称获取 Provider ID
func getProviderIDByName(name string) string {
	providersMu.RLock()
	defer providersMu.RUnlock()

	for id, provider := range apiProviders {
		if provider.Name == name {
			return id
		}
	}
	return ""
}

// ---------- 工具函数 ----------

func generateID() string {
	// 生成唯一 ID: 16位随机十六进制字符串
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// 如果随机数生成失败，回退到时间戳+随机数
		timestamp := time.Now().UnixNano()
		random := strconv.FormatInt(timestamp%10000, 10)
		hash := md5.Sum([]byte(strconv.FormatInt(timestamp, 10) + random))
		return hex.EncodeToString(hash[:8])
	}
	return hex.EncodeToString(b)
}

// generateUserToken 生成用户访问 token（用于 M3U 和代理访问）
func generateUserToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 如果随机数生成失败，使用 MD5
		timestamp := time.Now().UnixNano()
		hash := md5.Sum([]byte(strconv.FormatInt(timestamp, 10) + "user_token"))
		return hex.EncodeToString(hash[:])
	}
	return hex.EncodeToString(b)
}

func sendJSON(ctx *fasthttp.RequestCtx, code int, data interface{}) {
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(code)

	response := APIResponse{
		Code: 200,
		Data: data,
	}

	if code != 200 {
		response.Code = code
		if msg, ok := data.(string); ok {
			response.Message = msg
			response.Data = nil
		}
	}

	jsonData, _ := json.Marshal(response)
	ctx.SetBody(jsonData)
}

func sendError(ctx *fasthttp.RequestCtx, code int, message string) {
	sendJSON(ctx, code, message)
}

func parseJSONBody(ctx *fasthttp.RequestCtx, v interface{}) error {
	return json.Unmarshal(ctx.PostBody(), v)
}

func getTokenFromHeader(ctx *fasthttp.RequestCtx) string {
	auth := string(ctx.Request.Header.Peek("Authorization"))
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// 简单的 token 验证（生产环境应该使用 JWT）
func validateToken(token string) (*User, bool) {
	// 简单实现：token 格式为 "token_userId_timestamp"
	parts := strings.Split(token, "_")
	if len(parts) != 3 {
		return nil, false
	}

	userId := parts[1]
	usersMu.RLock()
	user, exists := apiUsers[userId]
	usersMu.RUnlock()

	return user, exists
}

func authMiddleware(ctx *fasthttp.RequestCtx) bool {
	token := getTokenFromHeader(ctx)
	if token == "" {
		sendError(ctx, 401, "未登录")
		return false
	}

	user, valid := validateToken(token)
	if !valid {
		sendError(ctx, 401, "登录已过期")
		return false
	}

	// 检查是否需要修改密码（除了修改密码接口外，其他接口都需要检查）
	path := string(ctx.URI().PathOriginal())
	method := string(ctx.Method())
	isChangePasswordAPI := path == "/api/auth/change-password" && method == "POST"
	isLogoutAPI := path == "/api/auth/logout" && method == "POST"

	if user.NeedChangePassword && !isChangePasswordAPI && !isLogoutAPI {
		sendError(ctx, 403, "首次登录需要修改密码")
		return false
	}

	// 将用户信息存储在请求上下文中
	ctx.SetUserValue("user", user)
	return true
}

func adminMiddleware(ctx *fasthttp.RequestCtx) bool {
	if !authMiddleware(ctx) {
		return false
	}

	user := ctx.UserValue("user").(*User)
	if user.Role != "admin" {
		sendError(ctx, 403, "无权限")
		return false
	}

	return true
}

// ---------- API 处理函数 ----------

// AuthLogin 登录
func AuthLogin(ctx *fasthttp.RequestCtx) {
	var req LoginRequest
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	// 如果系统未初始化，返回需要初始化的标记
	if !systemInitialized && req.Username == "admin" {
		// 返回特殊标记，前端需要跳转到设置密码页面
		sendJSON(ctx, 200, map[string]interface{}{
			"needInit": true,
			"message":  "系统首次使用，请设置管理员密码",
			"username": "admin",
		})
		return
	}

	usersMu.RLock()
	var foundUser *User
	for _, u := range apiUsers {
		if u.Username == req.Username {
			foundUser = u
			break
		}
	}
	usersMu.RUnlock()

	if foundUser == nil || foundUser.Password != req.Password {
		sendError(ctx, 401, "用户名或密码错误")
		return
	}

	// 生成简单 token
	token := fmt.Sprintf("token_%s_%d", foundUser.ID, time.Now().Unix())

	response := LoginResponse{
		Token:              token,
		NeedChangePassword: foundUser.NeedChangePassword,
		UserInfo:           foundUser.ToSafeUser(),
	}

	sendJSON(ctx, 200, response)
}

// AuthInfo 获取当前用户信息
func AuthInfo(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	user := ctx.UserValue("user").(*User)
	sendJSON(ctx, 200, user.ToSafeUser())
}

// AuthChangePassword 修改密码
func AuthChangePassword(ctx *fasthttp.RequestCtx) {
	// 需要登录，但不检查是否需要修改密码
	token := getTokenFromHeader(ctx)
	if token == "" {
		sendError(ctx, 401, "未登录")
		return
	}

	user, valid := validateToken(token)
	if !valid {
		sendError(ctx, 401, "登录已过期")
		return
	}

	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if req.NewPassword == "" {
		sendError(ctx, 400, "新密码不能为空")
		return
	}

	usersMu.Lock()
	// 验证旧密码
	if req.OldPassword != user.Password {
		usersMu.Unlock()
		sendError(ctx, 400, "原密码错误")
		return
	}

	// 修改密码
	user.Password = req.NewPassword
	user.NeedChangePassword = false
	apiUsers[user.ID] = user
	usersMu.Unlock()

	saveUsers()

	sendJSON(ctx, 200, nil)
}

// GetSystemStatus 获取系统状态
func GetSystemStatus(ctx *fasthttp.RequestCtx) {
	sendJSON(ctx, 200, map[string]interface{}{
		"initialized": systemInitialized,
	})
}

// InitSystem 系统初始化（首次设置管理员密码）
func InitSystem(ctx *fasthttp.RequestCtx) {
	// 如果系统已初始化，拒绝访问
	if systemInitialized {
		sendError(ctx, 403, "系统已初始化")
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if req.Password == "" {
		sendError(ctx, 400, "密码不能为空")
		return
	}

	// 创建 admin 用户
	adminUser := &User{
		ID:                 "1",
		Username:           "admin",
		Password:           req.Password,
		Role:               "admin",
		AllowedProviders:   []string{},
		CreatedAt:          time.Now().Format("2006-01-02 15:04:05"),
		NeedChangePassword: false,
		Token:              generateUserToken(),
	}

	usersMu.Lock()
	apiUsers[adminUser.ID] = adminUser
	usersMu.Unlock()

	// 标记系统已初始化
	systemInitialized = true

	// 保存用户数据
	saveUsers()

	// 生成 token
	token := fmt.Sprintf("token_%s_%d", adminUser.ID, time.Now().Unix())

	response := LoginResponse{
		Token:              token,
		NeedChangePassword: false,
		UserInfo:           adminUser.ToSafeUser(),
	}

	log.Printf("系统首次初始化，管理员密码已设置")
	sendJSON(ctx, 200, response)
}

// GetUsers 获取用户列表
func GetUsers(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	usersMu.RLock()
	userList := make([]User, 0, len(apiUsers))
	for _, u := range apiUsers {
		userList = append(userList, u.ToSafeUser())
	}
	usersMu.RUnlock()

	sendJSON(ctx, 200, userList)
}

// CreateUser 创建用户
func CreateUser(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	var req struct {
		Username         string   `json:"username"`
		Password         string   `json:"password"`
		Role             string   `json:"role"`
		AllowedProviders []string `json:"allowedProviders"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if req.Username == "" || req.Password == "" {
		sendError(ctx, 400, "用户名和密码不能为空")
		return
	}

	// 普通用户必须选择 Provider
	if req.Role == "user" && len(req.AllowedProviders) == 0 {
		sendError(ctx, 400, "普通用户必须至少选择一个 Provider")
		return
	}

	// 检查用户名是否已存在
	usersMu.RLock()
	for _, u := range apiUsers {
		if u.Username == req.Username {
			usersMu.RUnlock()
			sendError(ctx, 400, "用户名已存在")
			return
		}
	}
	usersMu.RUnlock()

	newUser := &User{
		ID:               generateID(),
		Username:         req.Username,
		Password:         req.Password,
		Role:             req.Role,
		AllowedProviders: req.AllowedProviders,
		CreatedAt:        time.Now().Format("2006-01-02 15:04:05"),
		Token:            generateUserToken(),
	}

	usersMu.Lock()
	apiUsers[newUser.ID] = newUser
	usersMu.Unlock()

	saveUsers()

	sendJSON(ctx, 200, newUser.ToSafeUser())
}

// UpdateUser 更新用户
func UpdateUser(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	id := ctx.UserValue("id").(string)
	if id == "1" {
		sendError(ctx, 403, "不能修改管理员账号")
		return
	}

	var req struct {
		Username         string   `json:"username"`
		Password         string   `json:"password"`
		Role             string   `json:"role"`
		AllowedProviders []string `json:"allowedProviders"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	usersMu.Lock()
	user, exists := apiUsers[id]
	if !exists {
		usersMu.Unlock()
		sendError(ctx, 404, "用户不存在")
		return
	}

	if req.Username != "" {
		user.Username = req.Username
	}
	if req.Password != "" {
		user.Password = req.Password
	}
	if req.Role != "" {
		user.Role = req.Role
	}
	user.AllowedProviders = req.AllowedProviders
	usersMu.Unlock()

	saveUsers()

	sendJSON(ctx, 200, user.ToSafeUser())
}

// DeleteUser 删除用户
func DeleteUser(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	id := ctx.UserValue("id").(string)
	if id == "1" {
		sendError(ctx, 403, "不能删除管理员账号")
		return
	}

	usersMu.Lock()
	if _, exists := apiUsers[id]; !exists {
		usersMu.Unlock()
		sendError(ctx, 404, "用户不存在")
		return
	}
	delete(apiUsers, id)
	usersMu.Unlock()

	saveUsers()

	sendJSON(ctx, 200, nil)
}

// GetOnlineUsers 获取在线用户（按 IP+Token+TVG-ID 聚合）
func GetOnlineUsers(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	onlineUsers := VISIT_TRACKER.GetAllOnlineUsers()

	// 按 IP+Token+TVG-ID 聚合
	type GroupKey struct {
		IP    string
		Token string
		TvgID string
	}

	type GroupInfo struct {
		IP           string    `json:"ip"`
		Token        string    `json:"token"`
		TvgID        string    `json:"tvgId"`
		ChannelName  string    `json:"channelName"`
		ProviderName string    `json:"providerName"`
		RequestCount int       `json:"requestCount"`
		LastTime     time.Time `json:"lastTime"`
	}

	groups := make(map[GroupKey]*GroupInfo)

	for _, u := range onlineUsers {
		key := GroupKey{
			IP:    u.IP,
			Token: u.Token,
			TvgID: u.TvgID,
		}

		if group, exists := groups[key]; exists {
			// 更新最后访问时间和请求计数
			group.RequestCount++
			if u.Timestamp.After(group.LastTime) {
				group.LastTime = u.Timestamp
			}
		} else {
			// 创建新组
			info := &GroupInfo{
				IP:           u.IP,
				Token:        u.Token,
				TvgID:        u.TvgID,
				RequestCount: 1,
				LastTime:     u.Timestamp,
			}

			// 获取频道名称
			channelsMu.RLock()
			for _, providerChannels := range apiChannels {
				for _, ch := range providerChannels {
					if ch.TvgID == u.TvgID {
						info.ChannelName = ch.Name
						break
					}
				}
			}
			channelsMu.RUnlock()

			// 获取 Provider 名称
			if providerName, ok := PROVIDER_BY_TVG_ID.Load(u.TvgID); ok {
				providersMu.RLock()
				// PROVIDER_BY_TVG_ID 存储的是 providerName，需要在 apiProviders 中查找
				for _, p := range apiProviders {
					if p.Name == providerName.(string) {
						info.ProviderName = p.Name
						break
					}
				}
				providersMu.RUnlock()
			}

			groups[key] = info
		}
	}

	// 转换为切片
	var result []GroupInfo
	for _, group := range groups {
		result = append(result, *group)
	}

	sendJSON(ctx, 200, result)
}

// GetSubscribeURL 生成订阅地址
func GetSubscribeURL(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)

	// 获取参数
	providerName := string(ctx.QueryArgs().Peek("provider"))
	urlType := string(ctx.QueryArgs().Peek("type")) // "source" 或 "proxy"

	if providerName == "" {
		sendError(ctx, 400, "缺少必要参数")
		return
	}

	var subscribeURL string
	if urlType == "source" {
		// 数据源订阅地址: /名称.m3u
		subscribeURL = fmt.Sprintf("/%s.m3u?token=%s", providerName, currentUser.Token)
	} else {
		// 默认返回代理订阅地址: /drm/playlist/名称/token/playlist.m3u
		subscribeURL = fmt.Sprintf("/drm/playlist/%s/%s/playlist.m3u", providerName, currentUser.Token)
	}

	sendJSON(ctx, 200, map[string]string{
		"subscribeUrl": subscribeURL,
	})
}

// GetProxyURL 生成代理地址
func GetProxyURL(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)

	// 获取参数
	urlStr := string(ctx.QueryArgs().Peek("url"))
	tvgID := string(ctx.QueryArgs().Peek("tvgId"))

	if urlStr == "" || tvgID == "" {
		sendError(ctx, 400, "缺少必要参数")
		return
	}

	// 判断代理类型
	contentType := "m3u8"
	if strings.Contains(urlStr, ".mpd") || strings.Contains(urlStr, "mpd?") {
		contentType = "mpd"
	}

	// 检查该 TVG ID 对应的 Provider 是否启用了 ToFmp4OverHls
	toFmp4OverHls := false
	if providerName, ok := PROVIDER_BY_TVG_ID.Load(tvgID); ok {
		configsMu.RLock()
		if config, exists := CONFIGS_BY_PROVIDER[providerName.(string)]; exists {
			toFmp4OverHls = *config.ToFmp4OverHls
		}
		configsMu.RUnlock()
	}

	var proxyURL string
	if toFmp4OverHls && contentType == "mpd" {
		// MPD 转 HLS，返回 index.m3u8 格式
		proxyURL = fmt.Sprintf("/drm/proxy/%s/%s/%s/index.m3u8", contentType, tvgID, currentUser.Token)
	} else {
		// 普通代理地址
		proxyURL = convert_to_proxy_url(contentType, tvgID, urlStr, "", "", currentUser.Token)
	}

	sendJSON(ctx, 200, map[string]string{
		"proxyUrl": proxyURL,
		"type":     contentType,
	})
}

// GetProviders 获取 Provider 列表
func GetProviders(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)

	providersMu.RLock()
	providerList := make([]Provider, 0, len(apiProviders))
	for _, p := range apiProviders {
		// 非管理员只能看到允许的 Provider
		if currentUser.Role != "admin" {
			allowed := false
			for _, id := range currentUser.AllowedProviders {
				if id == p.ID {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}
		providerList = append(providerList, *p)
	}
	providersMu.RUnlock()

	// 按名称排序
	sort.Slice(providerList, func(i, j int) bool {
		return providerList[i].Name < providerList[j].Name
	})

	sendJSON(ctx, 200, providerList)
}

// GetProvider 获取单个 Provider
func GetProvider(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)
	id := ctx.UserValue("id").(string)

	providersMu.RLock()
	provider, exists := apiProviders[id]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	// 非管理员只能访问允许的 Provider
	if currentUser.Role != "admin" {
		allowed := false
		for _, allowedID := range currentUser.AllowedProviders {
			if allowedID == id {
				allowed = true
				break
			}
		}
		if !allowed {
			sendError(ctx, 403, "无权限访问此 Provider")
			return
		}
	}

	sendJSON(ctx, 200, provider)
}

// CreateProvider 创建 Provider
func CreateProvider(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	var req struct {
		Name          string         `json:"name"`
		Type          string         `json:"type"`
		URL           string         `json:"url"`
		Headers       []string       `json:"headers"`
		StreamHeaders []string       `json:"streamHeaders"`
		Proxy         string         `json:"proxy"`
		StreamProxy   string         `json:"streamProxy"`
		Config        ProviderConfig `json:"config"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if req.Name == "" {
		sendError(ctx, 400, "名称不能为空")
		return
	}

	// 检查名称是否已存在
	providersMu.RLock()
	for _, p := range apiProviders {
		if p.Name == req.Name {
			providersMu.RUnlock()
			sendError(ctx, 400, "Provider 名称已存在")
			return
		}
	}
	providersMu.RUnlock()

	provider := &Provider{
		ID:            generateID(),
		Name:          req.Name,
		Type:          req.Type,
		URL:           req.URL,
		Headers:       req.Headers,
		StreamHeaders: req.StreamHeaders,
		Proxy:         req.Proxy,
		StreamProxy:   req.StreamProxy,
		ChannelCount:  0,
		Config:        req.Config,
		Status:        "loading",
		StatusMessage: "正在初始化...",
	}

	providersMu.Lock()
	apiProviders[provider.ID] = provider
	providersMu.Unlock()

	// 初始化频道存储
	channelsMu.Lock()
	if apiChannels[provider.ID] == nil {
		apiChannels[provider.ID] = make(map[string]*Channel)
	}
	channelsMu.Unlock()

	// 注册到运行时（创建 HTTP 客户端、缓存等）
	registerProviderRuntime(provider)

	saveProviders()
	saveChannels()

	// 异步加载 M3U（所有类型都需要初始化）
	go func() {
		loadM3u(nil, provider.Name, "")
	}()

	sendJSON(ctx, 200, provider)
}

// UpdateProvider 更新 Provider
func UpdateProvider(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	id := ctx.UserValue("id").(string)

	var req struct {
		Name          string         `json:"name"`
		Type          string         `json:"type"`
		URL           string         `json:"url"`
		Headers       []string       `json:"headers"`
		StreamHeaders []string       `json:"streamHeaders"`
		Proxy         string         `json:"proxy"`
		StreamProxy   string         `json:"streamProxy"`
		Config        ProviderConfig `json:"config"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	providersMu.Lock()
	provider, exists := apiProviders[id]
	if !exists {
		providersMu.Unlock()
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	// 如果名称变化，需要先注销旧名称的运行时
	oldName := provider.Name
	nameChanged := req.Name != "" && req.Name != provider.Name

	if req.Name != "" {
		provider.Name = req.Name
	}
	if req.Type != "" {
		provider.Type = req.Type
	}
	provider.URL = req.URL
	provider.Headers = req.Headers
	provider.StreamHeaders = req.StreamHeaders
	provider.Proxy = req.Proxy
	provider.StreamProxy = req.StreamProxy
	provider.Config = req.Config
	providersMu.Unlock()

	// 如果配置发生变化，先停止相关的 Updater，然后重新注册运行时
	if nameChanged {
		unregisterProviderRuntime(oldName)
		stopUpdatersByProvider(oldName)
	} else {
		stopUpdatersByProvider(provider.Name)
	}
	registerProviderRuntime(provider)

	saveProviders()

	sendJSON(ctx, 200, provider)
}

// DeleteProvider 删除 Provider
func DeleteProvider(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	id := ctx.UserValue("id").(string)

	providersMu.Lock()
	provider, exists := apiProviders[id]
	if !exists {
		providersMu.Unlock()
		sendError(ctx, 404, "Provider 不存在")
		return
	}
	providerName := provider.Name
	delete(apiProviders, id)
	providersMu.Unlock()

	// 从运行时注销（删除 HTTP 客户端、缓存等）
	unregisterProviderRuntime(providerName)

	// 删除关联的频道
	channelsMu.Lock()
	delete(apiChannels, id)
	channelsMu.Unlock()

	saveProviders()
	saveChannels()

	sendJSON(ctx, 200, nil)
}

// RefreshProviderChannels 刷新 Provider 频道（仅远程类型）
func RefreshProviderChannels(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	id := ctx.UserValue("id").(string)

	providersMu.RLock()
	provider, exists := apiProviders[id]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	if provider.Type != "remote" {
		sendError(ctx, 400, "仅远程 M3U 类型支持刷新")
		return
	}

	// 重新加载 M3U 文件
	loadM3u(nil, provider.Name, "")

	// 获取更新后的频道数量
	channelsMu.RLock()
	channelCount := len(apiChannels[id])
	channelsMu.RUnlock()

	provider.ChannelCount = channelCount
	saveProviders()

	sendJSON(ctx, 200, map[string]int{"channelCount": channelCount})
}

// GetChannels 获取频道列表
func GetChannels(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)
	providerId := ctx.UserValue("providerId").(string)

	// 非管理员只能访问允许的 Provider
	if currentUser.Role != "admin" {
		allowed := false
		for _, allowedID := range currentUser.AllowedProviders {
			if allowedID == providerId {
				allowed = true
				break
			}
		}
		if !allowed {
			sendError(ctx, 403, "无权限访问此 Provider")
			return
		}
	}

	// 解析查询参数
	page := 1
	pageSize := 10
	search := ""
	group := ""

	if p := string(ctx.QueryArgs().Peek("page")); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := string(ctx.QueryArgs().Peek("pageSize")); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	search = string(ctx.QueryArgs().Peek("search"))
	group = string(ctx.QueryArgs().Peek("group"))

	providersMu.RLock()
	provider, exists := apiProviders[providerId]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	channelsMu.RLock()
	providerChannels := apiChannels[providerId]
	if providerChannels == nil {
		providerChannels = make(map[string]*Channel)
	}

	// 收集所有频道
	allChannels := make([]*Channel, 0, len(providerChannels))
	for _, ch := range providerChannels {
		allChannels = append(allChannels, ch)
	}
	channelsMu.RUnlock()

	// 按名称倒序排序，确保顺序一致
	sort.Slice(allChannels, func(i, j int) bool {
		return allChannels[i].Name > allChannels[j].Name
	})

	// 搜索过滤
	if search != "" {
		searchLower := strings.ToLower(search)
		filtered := make([]*Channel, 0)
		for _, ch := range allChannels {
			if strings.Contains(strings.ToLower(ch.Name), searchLower) {
				filtered = append(filtered, ch)
			}
		}
		allChannels = filtered
	}

	// 分组过滤
	if group != "" {
		filtered := make([]*Channel, 0)
		for _, ch := range allChannels {
			if ch.GroupTitle == group {
				filtered = append(filtered, ch)
			}
		}
		allChannels = filtered
	}

	// 获取所有分组
	groupSet := make(map[string]bool)
	channelsMu.RLock()
	for _, ch := range apiChannels[providerId] {
		if ch.GroupTitle != "" {
			groupSet[ch.GroupTitle] = true
		}
	}
	channelsMu.RUnlock()

	groupList := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groupList = append(groupList, g)
	}

	// 分页
	total := len(allChannels)
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > total {
		start = total
	}
	if end > total {
		end = total
	}

	var list []Channel
	if start < total {
		pageChannels := allChannels[start:end]
		list = make([]Channel, len(pageChannels))
		for i, ch := range pageChannels {
			list[i] = *ch
		}
	} else {
		list = []Channel{}
	}

	response := ChannelListResponse{
		List:         list,
		Total:        total,
		Groups:       groupList,
		ProviderName: provider.Name,
	}

	sendJSON(ctx, 200, response)
}

// GetAllChannels 获取所有频道（跨所有 Provider）
func GetAllChannels(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	currentUser := ctx.UserValue("user").(*User)

	// 解析查询参数
	page := 1
	pageSize := 10
	search := ""
	group := ""
	providerFilter := ""

	if p := string(ctx.QueryArgs().Peek("page")); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if ps := string(ctx.QueryArgs().Peek("pageSize")); ps != "" {
		if v, err := strconv.Atoi(ps); err == nil && v > 0 {
			pageSize = v
		}
	}
	search = string(ctx.QueryArgs().Peek("search"))
	group = string(ctx.QueryArgs().Peek("group"))
	providerFilter = string(ctx.QueryArgs().Peek("provider"))

	// 收集所有频道
	type ChannelWithProvider struct {
		Channel
		ProviderID   string `json:"providerId"`
		ProviderName string `json:"providerName"`
		ProviderType string `json:"providerType"`
	}

	channelsMu.RLock()
	providersMu.RLock()

	allChannels := make([]ChannelWithProvider, 0)
	groupSet := make(map[string]bool)

	for providerId, providerChannels := range apiChannels {
		provider, exists := apiProviders[providerId]
		if !exists {
			continue
		}

		// 非管理员只能访问允许的 Provider
		if currentUser.Role != "admin" {
			allowed := false
			for _, allowedID := range currentUser.AllowedProviders {
				if allowedID == providerId {
					allowed = true
					break
				}
			}
			if !allowed {
				continue
			}
		}

		// Provider 过滤
		if providerFilter != "" && providerId != providerFilter {
			continue
		}

		for _, ch := range providerChannels {
			if ch.GroupTitle != "" {
				groupSet[ch.GroupTitle] = true
			}

			allChannels = append(allChannels, ChannelWithProvider{
				Channel:      *ch,
				ProviderID:   providerId,
				ProviderName: provider.Name,
				ProviderType: provider.Type,
			})
		}
	}

	providersMu.RUnlock()
	channelsMu.RUnlock()

	// 按名称倒序排序
	sort.Slice(allChannels, func(i, j int) bool {
		return allChannels[i].Name > allChannels[j].Name
	})

	// 搜索过滤
	if search != "" {
		searchLower := strings.ToLower(search)
		filtered := make([]ChannelWithProvider, 0)
		for _, ch := range allChannels {
			if strings.Contains(strings.ToLower(ch.Name), searchLower) ||
				strings.Contains(strings.ToLower(ch.TvgID), searchLower) {
				filtered = append(filtered, ch)
			}
		}
		allChannels = filtered
	}

	// 分组过滤
	if group != "" {
		filtered := make([]ChannelWithProvider, 0)
		for _, ch := range allChannels {
			if ch.GroupTitle == group {
				filtered = append(filtered, ch)
			}
		}
		allChannels = filtered
	}

	// 获取所有分组
	groupList := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groupList = append(groupList, g)
	}

	// 分页（pageSize 为 -1 时返回所有数据）
	total := len(allChannels)
	var list []ChannelWithProvider
	if pageSize == -1 {
		// 返回所有数据
		list = allChannels
	} else {
		start := (page - 1) * pageSize
		end := start + pageSize
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}
		if start < total {
			list = allChannels[start:end]
		} else {
			list = []ChannelWithProvider{}
		}
	}

	sendJSON(ctx, 200, map[string]interface{}{
		"list":   list,
		"total":  total,
		"groups": groupList,
	})
}

// CreateChannel 创建频道
func CreateChannel(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	providerId := ctx.UserValue("providerId").(string)

	providersMu.RLock()
	provider, exists := apiProviders[providerId]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	if provider.Type != "custom" {
		sendError(ctx, 400, "仅自定义类型支持添加频道")
		return
	}

	var req Channel
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	if req.Name == "" || req.URL == "" || req.TvgID == "" {
		sendError(ctx, 400, "频道名称、TVG ID 和 URL 不能为空")
		return
	}

	channel := &Channel{
		ID:         generateID(),
		Name:       req.Name,
		TvgID:      req.TvgID,
		GroupTitle: req.GroupTitle,
		Logo:       req.Logo,
		URL:        req.URL,
		Enabled:    req.Enabled,
		DRM:        req.DRM,
	}

	channelsMu.Lock()
	if apiChannels[providerId] == nil {
		apiChannels[providerId] = make(map[string]*Channel)
	}
	apiChannels[providerId][channel.ID] = channel

	// 更新频道数量
	provider.ChannelCount = len(apiChannels[providerId])
	channelsMu.Unlock()

	// 注册 TVG ID 到全局映射（用于代理）
	PROVIDER_BY_TVG_ID.Store(channel.TvgID, provider.Name)
	RAW_URL_BY_TVG_ID.Store(channel.TvgID, channel.URL)
	
	// 如果有 DRM 配置，更新 clearKeysMap
	if channel.DRM != nil && channel.DRM.Type == "clearkey" && channel.DRM.Value != "" {
		clearKeysMap.Store(channel.TvgID, channel.DRM.Value)
	} else {
		// 如果没有 DRM 配置，清除可能存在的旧值
		clearKeysMap.Delete(channel.TvgID)
	}

	saveChannels()
	saveProviders()

	sendJSON(ctx, 200, channel)
}

// GetChannel 获取单个频道
func GetChannel(ctx *fasthttp.RequestCtx) {
	if !authMiddleware(ctx) {
		return
	}

	providerId := ctx.UserValue("providerId").(string)
	channelId := ctx.UserValue("channelId").(string)

	channelsMu.RLock()
	channel, exists := apiChannels[providerId][channelId]
	channelsMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "频道不存在")
		return
	}

	sendJSON(ctx, 200, channel)
}

// UpdateChannel 更新频道
func UpdateChannel(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	providerId := ctx.UserValue("providerId").(string)
	channelId := ctx.UserValue("channelId").(string)

	providersMu.RLock()
	provider, exists := apiProviders[providerId]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	var req Channel
	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	channelsMu.Lock()
	channel, exists := apiChannels[providerId][channelId]
	if !exists {
		channelsMu.Unlock()
		sendError(ctx, 404, "频道不存在")
		return
	}

	if req.Name != "" {
		channel.Name = req.Name
	}
	if req.TvgID != "" {
		channel.TvgID = req.TvgID
	}
	channel.GroupTitle = req.GroupTitle
	channel.Logo = req.Logo
	if req.URL != "" {
		channel.URL = req.URL
	}
	channel.Enabled = req.Enabled
	channel.DRM = req.DRM
	channelsMu.Unlock()

	// 更新 TVG ID 映射（用于代理）
	PROVIDER_BY_TVG_ID.Store(channel.TvgID, provider.Name)
	RAW_URL_BY_TVG_ID.Store(channel.TvgID, channel.URL)
	
	// 如果有 DRM 配置，更新 clearKeysMap
	if channel.DRM != nil && channel.DRM.Type == "clearkey" && channel.DRM.Value != "" {
		clearKeysMap.Store(channel.TvgID, channel.DRM.Value)
	} else {
		// 如果没有 DRM 配置，清除可能存在的旧值
		clearKeysMap.Delete(channel.TvgID)
	}

	saveChannels()

	sendJSON(ctx, 200, channel)
}

// ToggleChannel 启用/禁用频道
func ToggleChannel(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	providerId := ctx.UserValue("providerId").(string)
	channelId := ctx.UserValue("channelId").(string)

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := parseJSONBody(ctx, &req); err != nil {
		sendError(ctx, 400, "请求格式错误")
		return
	}

	channelsMu.Lock()
	channel, exists := apiChannels[providerId][channelId]
	if !exists {
		channelsMu.Unlock()
		sendError(ctx, 404, "频道不存在")
		return
	}

	channel.Enabled = req.Enabled
	channelsMu.Unlock()

	saveChannels()

	sendJSON(ctx, 200, nil)
}

// DeleteChannel 删除频道
func DeleteChannel(ctx *fasthttp.RequestCtx) {
	if !adminMiddleware(ctx) {
		return
	}

	providerId := ctx.UserValue("providerId").(string)
	channelId := ctx.UserValue("channelId").(string)

	providersMu.RLock()
	provider, exists := apiProviders[providerId]
	providersMu.RUnlock()

	if !exists {
		sendError(ctx, 404, "Provider 不存在")
		return
	}

	if provider.Type != "custom" {
		sendError(ctx, 400, "仅自定义类型支持删除频道")
		return
	}

	channelsMu.Lock()
	channel, exists := apiChannels[providerId][channelId]
	if !exists {
		channelsMu.Unlock()
		sendError(ctx, 404, "频道不存在")
		return
	}
	
	// 删除前记录 TvgID，用于清除 clearKeysMap
	tvgID := channel.TvgID
	
	delete(apiChannels[providerId], channelId)

	// 更新频道数量
	provider.ChannelCount = len(apiChannels[providerId])
	channelsMu.Unlock()
	
	// 清除 clearKeysMap 中的对应条目
	clearKeysMap.Delete(tvgID)

	saveChannels()
	saveProviders()

	sendJSON(ctx, 200, nil)
}

// ---------- 路由处理 ----------

// APIHandler 处理 API 请求
func APIHandler(ctx *fasthttp.RequestCtx) {
	path := string(ctx.URI().PathOriginal())
	method := string(ctx.Method())

	// 移除 /api 前缀
	path = strings.TrimPrefix(path, "/api")

	// 设置 CORS 头
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
	ctx.Response.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS")
	ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if method == "OPTIONS" {
		ctx.SetStatusCode(200)
		return
	}

	// 路由匹配
	switch {
	// 认证相关
	case path == "/auth/login" && method == "POST":
		AuthLogin(ctx)
	case path == "/auth/info" && method == "GET":
		AuthInfo(ctx)
	case path == "/auth/change-password" && method == "POST":
		AuthChangePassword(ctx)
	case path == "/auth/init" && method == "POST":
		InitSystem(ctx)
	case path == "/auth/status" && method == "GET":
		GetSystemStatus(ctx)

	// 用户管理
	case path == "/users" && method == "GET":
		GetUsers(ctx)
	case path == "/users" && method == "POST":
		CreateUser(ctx)
	case strings.HasPrefix(path, "/users/") && method == "PUT":
		id := strings.TrimPrefix(path, "/users/")
		ctx.SetUserValue("id", id)
		UpdateUser(ctx)
	case strings.HasPrefix(path, "/users/") && method == "DELETE":
		id := strings.TrimPrefix(path, "/users/")
		ctx.SetUserValue("id", id)
		DeleteUser(ctx)

	// Channel 管理（必须在 Provider 管理之前，因为 /providers/{id}/channels 包含 /providers/）
	case path == "/all-channels" && method == "GET":
		GetAllChannels(ctx)
	case strings.Contains(path, "/channels"):
		handleChannelRoutes(ctx, path, method)

	// Provider 管理
	case path == "/providers" && method == "GET":
		GetProviders(ctx)
	case path == "/providers" && method == "POST":
		CreateProvider(ctx)
	case strings.HasPrefix(path, "/providers/"):
		handleProviderRoutes(ctx, path, method)

	// 监控管理
	case path == "/monitor/online-users" && method == "GET":
		GetOnlineUsers(ctx)

	// 代理地址生成
	case path == "/proxy-url" && method == "GET":
		GetProxyURL(ctx)

	// 订阅地址生成
	case path == "/subscribe-url" && method == "GET":
		GetSubscribeURL(ctx)

	default:
		sendError(ctx, 404, "API 不存在")
	}
}

func handleProviderRoutes(ctx *fasthttp.RequestCtx, path, method string) {
	// 处理 /providers/{id} 和 /providers/{id}/refresh
	parts := strings.Split(strings.TrimPrefix(path, "/providers/"), "/")
	if len(parts) == 0 {
		sendError(ctx, 404, "Provider ID 不能为空")
		return
	}

	id := parts[0]

	if len(parts) == 1 {
		switch method {
		case "GET":
			ctx.SetUserValue("id", id)
			GetProvider(ctx)
		case "PUT":
			ctx.SetUserValue("id", id)
			UpdateProvider(ctx)
		case "DELETE":
			ctx.SetUserValue("id", id)
			DeleteProvider(ctx)
		default:
			sendError(ctx, 405, "方法不允许")
		}
		return
	}

	if len(parts) == 2 && parts[1] == "refresh" && method == "POST" {
		ctx.SetUserValue("id", id)
		RefreshProviderChannels(ctx)
		return
	}

	sendError(ctx, 404, "API 不存在")
}

func handleChannelRoutes(ctx *fasthttp.RequestCtx, path, method string) {
	// 解析 /providers/{providerId}/channels/{channelId}
	// 格式: /providers/{id}/channels 或 /providers/{id}/channels/{channelId}

	parts := strings.Split(path, "/")
	if len(parts) < 4 || parts[0] != "" || parts[1] != "providers" || parts[3] != "channels" {
		sendError(ctx, 404, "API 路径错误")
		return
	}

	providerId := parts[2]

	if len(parts) == 4 {
		// /providers/{providerId}/channels
		switch method {
		case "GET":
			ctx.SetUserValue("providerId", providerId)
			GetChannels(ctx)
		case "POST":
			ctx.SetUserValue("providerId", providerId)
			CreateChannel(ctx)
		default:
			sendError(ctx, 405, "方法不允许")
		}
		return
	}

	if len(parts) == 5 {
		// /providers/{providerId}/channels/{channelId}
		channelId := parts[4]
		ctx.SetUserValue("providerId", providerId)
		ctx.SetUserValue("channelId", channelId)

		switch method {
		case "GET":
			GetChannel(ctx)
		case "PUT":
			UpdateChannel(ctx)
		case "PATCH":
			ToggleChannel(ctx)
		case "DELETE":
			DeleteChannel(ctx)
		default:
			sendError(ctx, 405, "方法不允许")
		}
		return
	}

	sendError(ctx, 404, "API 不存在")
}
