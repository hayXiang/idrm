package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"strings"
)

// StreamConfig 流配置
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

// loadConfigFile 从 JSON 文件加载配置
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

// ConfigLoader 配置加载器
type ConfigLoader struct {
	defaultValues DefaultConfigValues
}

// DefaultConfigValues 默认配置值
type DefaultConfigValues struct {
	BestQuality              bool
	ToFmp4OverHls            bool
	SpeedUp                  bool
	HttpTimeout              int
	ManifestCacheExpire      int
	SegmentMemoryCacheExpire int
	SegmentFileCacheExpire   int
	M3uUserAgent             string
	UserAgent                string
}

// NewConfigLoader 创建配置加载器
func NewConfigLoader(defaults DefaultConfigValues) *ConfigLoader {
	return &ConfigLoader{
		defaultValues: defaults,
	}
}

// LoadFromFile 从配置文件加载
func (cl *ConfigLoader) LoadFromFile(configFile string) ([]StreamConfig, error) {
	if configFile == "" {
		return nil, errors.New("配置文件路径为空")
	}

	configs, err := loadConfigFile(configFile)
	if err != nil {
		return nil, err
	}

	// 应用默认值
	for i := range configs {
		cl.applyDefaults(&configs[i])
	}

	return configs, nil
}

// LoadFromFlags 从命令行参数加载单个配置
func (cl *ConfigLoader) LoadFromFlags(name, input string, headers []string, userAgent *string, userSet bool, proxyURL, m3uProxy, m3uUserAgent string) []StreamConfig {
	var us *string = nil
	if userSet {
		us = userAgent
	}

	config := StreamConfig{
		Name:                     name,
		URL:                      input,
		Headers:                  headers,
		UserAgent:                us,
		Proxy:                    proxyURL,
		M3uProxy:                 m3uProxy,
		M3uUserAgent:             &m3uUserAgent,
		BestQuality:              &cl.defaultValues.BestQuality,
		ToFmp4OverHls:            &cl.defaultValues.ToFmp4OverHls,
		HttpTimeout:              &cl.defaultValues.HttpTimeout,
		SegmentMemoryCacheExpire: &cl.defaultValues.SegmentMemoryCacheExpire,
		SegmentFileCacheExpire:   &cl.defaultValues.SegmentFileCacheExpire,
		ManifestCacheExpire:      &cl.defaultValues.ManifestCacheExpire,
		SpeedUp:                  &cl.defaultValues.SpeedUp,
	}

	return []StreamConfig{config}
}

// LoadEmpty 加载空配置（仅 API 模式）
func (cl *ConfigLoader) LoadEmpty() []StreamConfig {
	log.Printf("警告: 没有提供配置文件或输入参数，仅 API 服务可用")
	return []StreamConfig{}
}

// applyDefaults 应用默认值
func (cl *ConfigLoader) applyDefaults(config *StreamConfig) {
	if config.M3uUserAgent == nil {
		ua := cl.defaultValues.M3uUserAgent
		config.M3uUserAgent = &ua
	}

	if config.BestQuality == nil {
		bq := cl.defaultValues.BestQuality
		config.BestQuality = &bq
	}

	if config.ToFmp4OverHls == nil {
		tf := cl.defaultValues.ToFmp4OverHls
		config.ToFmp4OverHls = &tf
	}

	if config.HttpTimeout == nil {
		ht := cl.defaultValues.HttpTimeout
		config.HttpTimeout = &ht
	}

	if config.ManifestCacheExpire == nil {
		mc := cl.defaultValues.ManifestCacheExpire
		config.ManifestCacheExpire = &mc
	}

	if config.SegmentFileCacheExpire == nil {
		sf := cl.defaultValues.SegmentFileCacheExpire
		config.SegmentFileCacheExpire = &sf
	}

	if config.SegmentMemoryCacheExpire == nil {
		sm := cl.defaultValues.SegmentMemoryCacheExpire
		config.SegmentMemoryCacheExpire = &sm
	}

	if config.SpeedUp == nil {
		su := cl.defaultValues.SpeedUp
		config.SpeedUp = &su
	}
}

// ProcessHeaders 处理 User-Agent 优先级
func ProcessHeaders(configs []StreamConfig) []StreamConfig {
	for i := range configs {
		var userAgentIndex = -1
		for j, h := range configs[i].Headers {
			parts := strings.SplitN(h, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			value := strings.TrimSpace(parts[1])
			if key == "user-agent" {
				userAgentIndex = j
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

		if userAgentIndex != -1 {
			// 覆盖已有的 User-Agent
			configs[i].Headers[userAgentIndex] = "User-Agent: " + *configs[i].UserAgent
		} else {
			// 添加新的 User-Agent
			configs[i].Headers = append(configs[i].Headers, "User-Agent: "+*configs[i].UserAgent)
		}
	}
	return configs
}
