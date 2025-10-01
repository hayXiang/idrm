package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"idrm/utils"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
	"github.com/valyala/fasthttp"
)

type MyMetadata struct {
	FileType string `json:"file_type"`
	UUID     string `json:"uuid"`
	FileSize int64  `json:"file_size"`
}

// 保存到文件
func SaveMetadata(filePath string, meta MyMetadata) error {
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// 从文件读取
func LoadMetadata(filePath string) (*MyMetadata, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	var meta MyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// 缓存项
type CacheItem struct {
	Data     []byte
	Metadata MyMetadata
}

// 写任务
type fileTask struct {
	key  string
	item CacheItem
}

type MyCache struct {
	memCache  *cache.Cache
	dir       string
	fileTTL   int
	memTTL    int
	mu        sync.RWMutex
	writeChan chan fileTask
	wg        sync.WaitGroup
	stopCh    chan struct{}
}

// NewMyCache 创建文件缓存
// memTTL: 内存缓存默认时间
// fileTTL: 文件缓存默认时间 (如果 fileTTL == -1，则不启用文件缓存)
func NewMyCache(dir string, memTTL int, fileTTL int) *MyCache {
	fc := &MyCache{
		memCache:  cache.New(time.Duration(memTTL)*time.Second, time.Duration(2*memTTL)*time.Second),
		dir:       dir,
		fileTTL:   fileTTL,
		memTTL:    memTTL,
		writeChan: make(chan fileTask, 100),
		stopCh:    make(chan struct{}),
	}

	if fileTTL >= 0 {
		os.MkdirAll(dir, 0755)
		fc.wg.Add(1)
		go fc.writeWorker()
		go fc.cleanupLoop()
	}
	return fc
}

// 生成文件名：<原始文件名>_<md5(key)>
func fileNameFromKey(key string) string {
	base := filepath.Base(key)
	base = strings.Split(base, "?")[0]
	h := md5.Sum([]byte(key))
	md5Str := hex.EncodeToString(h[:])
	return base + "_" + md5Str
}

// 异步写文件 worker
func (fc *MyCache) writeWorker() {
	defer fc.wg.Done()
	for {
		select {
		case task := <-fc.writeChan:
			fc.writeFile(task.key, task.item)
		case <-fc.stopCh:
			// drain 模式，处理剩余任务
			for task := range fc.writeChan {
				fc.writeFile(task.key, task.item)
			}
			return
		}
	}
}

// 真正写文件 (原子写)
func (fc *MyCache) writeFile(key string, item CacheItem) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	dataPath := filepath.Join(fc.dir, key+".idrm-data")
	metaPath := filepath.Join(fc.dir, key+".idrm-meta")

	tmpData := dataPath + ".tmp"
	tmpMeta := metaPath + ".tmp"

	_ = os.Remove(tmpData)
	_ = os.Remove(tmpMeta)

	if err := os.WriteFile(tmpData, item.Data, 0644); err == nil {
		_ = os.Rename(tmpData, dataPath)
	}

	info, err := os.Stat(dataPath)
	if err == nil {
		item.Metadata.FileSize = info.Size()
	}
	if err := SaveMetadata(tmpMeta, item.Metadata); err == nil {
		_ = os.Rename(tmpMeta, metaPath)
	}
}

// Set 缓存数据
func (fc *MyCache) Set(key string, data []byte, metadat MyMetadata) {
	if fc.memTTL < 0 && fc.fileTTL < 0 {
		return
	}

	key = fileNameFromKey(key)
	item := CacheItem{Data: data, Metadata: metadat}
	if fc.memTTL >= 0 {
		// 存内存
		fc.memCache.Set(key, item, time.Duration(fc.memTTL)*time.Second)
	}

	// 文件缓存禁用
	if fc.fileTTL >= 0 {
		select {
		case fc.writeChan <- fileTask{key: key, item: item}:
		default:
		}
	}
}

// Get 获取缓存
func (fc *MyCache) Get(key string) ([]byte, string, bool, error) {
	key = fileNameFromKey(key)

	if val, ok := fc.memCache.Get(key); ok {
		item := val.(CacheItem)
		return item.Data, item.Metadata.FileType, true, nil
	}

	if fc.fileTTL < 0 {
		return nil, "", false, nil
	}

	fc.mu.RLock()
	defer fc.mu.RUnlock()

	dataPath := filepath.Join(fc.dir, key+".idrm-data")
	metaPath := filepath.Join(fc.dir, key+".idrm-meta")

	info, err := os.Stat(dataPath)
	if err != nil {
		return nil, "", false, nil
	}
	if fc.fileTTL > 0 && time.Since(info.ModTime()) > time.Duration(fc.fileTTL)*time.Second {
		_ = os.Remove(dataPath)
		_ = os.Remove(metaPath)
		return nil, "", false, nil
	}

	data, err := os.ReadFile(dataPath)
	if err != nil {
		return nil, "", false, err
	}
	metadata, err := LoadMetadata(metaPath)
	if err != nil {
		return nil, "", false, err
	}

	item := CacheItem{Data: data, Metadata: *metadata}
	if fc.memTTL >= 0 {
		fc.memCache.Set(key, item, time.Duration(fc.memTTL)*time.Second)
	}
	return item.Data, item.Metadata.FileType, true, nil
}

// Delete 删除缓存
func (fc *MyCache) Delete(key string) {
	key = fileNameFromKey(key)
	fc.memCache.Delete(key)
	if fc.fileTTL < 0 {
		return
	}

	fc.mu.Lock()
	defer fc.mu.Unlock()

	_ = os.Remove(filepath.Join(fc.dir, key+".idrm-data"))
	_ = os.Remove(filepath.Join(fc.dir, key+".idrm-meta"))
}

// cleanupLoop 定时清理过期文件
func (fc *MyCache) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-fc.stopCh:
			return
		case <-ticker.C:
			files, _ := os.ReadDir(fc.dir)
			now := time.Now()
			for _, file := range files {
				ext := filepath.Ext(file.Name())
				if ext != ".idrm-data" && ext != ".idrm-meta" {
					continue
				}
				path := filepath.Join(fc.dir, file.Name())
				info, err := os.Stat(path)
				if err == nil && fc.fileTTL > 0 && now.Sub(info.ModTime()) > time.Duration(fc.fileTTL)*time.Second {
					_ = os.Remove(path)
				}
			}
		}
	}
}

// Close 优雅关闭
func (fc *MyCache) Close() {
	close(fc.stopCh)
	fc.wg.Wait()
}

type CacheSummary struct {
	Count          int    `json:"count"`
	TotalSize      string `json:"total_size"`
	TotalSizeBytes int64  `json:"total_size_bytes"`
}

type CacheReportItem struct {
	Manifest CacheSummary `json:"manifest"`
	Memory   CacheSummary `json:"memory"`
	File     CacheSummary `json:"file"`
	Total    CacheSummary `json:"total"`
}

type CacheReport struct {
	Total     CacheReportItem                       `json:"total"`
	Providers map[string]map[string]CacheReportItem `json:"providers"`
}

// 异步统计单个 FileCache 中所有 tvgId 的缓存报告
func generateProviderCacheReport(fc *MyCache) map[string]CacheReportItem {
	result := make(map[string]CacheReportItem)
	if fc == nil {
		return result
	}

	files, _ := os.ReadDir(fc.dir)
	var fileSizesByTvgId = make(map[string][]int64)
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if !strings.Contains(f.Name(), ".idrm-meta") {
			continue
		}

		if metadata, err := LoadMetadata(fc.dir + "/" + f.Name()); err == nil {
			fileSizesByTvgId[metadata.UUID] = append(fileSizesByTvgId[metadata.UUID], metadata.FileSize)
		}
	}

	var cacheItemsByTvgId = make(map[string][]*cache.Item)

	// 按 tvgId 分组
	for _, v := range fc.memCache.Items() {
		tvgId := v.Object.(CacheItem).Metadata.UUID
		item := v // 拷贝一份，避免 &v 引用问题
		cacheItemsByTvgId[tvgId] = append(cacheItemsByTvgId[tvgId], &item)
	}

	// 文件缓存已知的先统计
	for tvgId, fileSizeList := range fileSizesByTvgId {
		result[tvgId] = generateTvgIdReport(fc, cacheItemsByTvgId[tvgId], fileSizeList)
	}

	// 补齐只有内存缓存、没有文件缓存的 tvgId
	for tvgId, items := range cacheItemsByTvgId {
		if _, ok := result[tvgId]; !ok {
			result[tvgId] = generateTvgIdReport(fc, items, []int64{})
		}
	}

	return result
}

// 单个 tvgId 的 FileCache 统计
func generateTvgIdReport(fc *MyCache, cacheItems []*cache.Item, fileSizeByTvgId []int64) CacheReportItem {
	var memCount, fileCount int
	var memSize, fileSize int64

	// 内存统计
	for _, item := range cacheItems {
		memCount++
		memSize += int64(len(item.Object.(CacheItem).Data))
	}

	// 文件统计
	for _, f := range fileSizeByTvgId {
		fileCount++
		fileSize += f
	}

	totalCount := memCount + fileCount
	totalSize := memSize + fileSize

	return CacheReportItem{
		Memory: CacheSummary{
			Count:          memCount,
			TotalSize:      utils.FormatSize(memSize),
			TotalSizeBytes: memSize,
		},
		File: CacheSummary{
			Count:          fileCount,
			TotalSize:      utils.FormatSize(fileSize),
			TotalSizeBytes: fileSize,
		},
		Total: CacheSummary{
			Count:          totalCount,
			TotalSize:      utils.FormatSize(totalSize),
			TotalSizeBytes: totalSize,
		},
	}
}

// 合并多个 CacheReportItem
func mergeReportItems(items ...CacheReportItem) CacheReportItem {
	var manifestCount, memCount, fileCount int
	var manifestSize, memSize, fileSize int64

	for _, r := range items {
		manifestCount += r.Manifest.Count
		manifestSize += r.Manifest.TotalSizeBytes
		memCount += r.Memory.Count
		memSize += r.Memory.TotalSizeBytes
		fileCount += r.File.Count
		fileSize += r.File.TotalSizeBytes
	}

	totalCount := manifestCount + memCount + fileCount
	totalSize := manifestSize + memSize + fileSize

	return CacheReportItem{
		Manifest: CacheSummary{
			Count:          manifestCount,
			TotalSize:      utils.FormatSize(manifestSize),
			TotalSizeBytes: manifestSize,
		},
		Memory: CacheSummary{
			Count:          memCount,
			TotalSize:      utils.FormatSize(memSize),
			TotalSizeBytes: memSize,
		},
		File: CacheSummary{
			Count:          fileCount,
			TotalSize:      utils.FormatSize(fileSize),
			TotalSizeBytes: fileSize,
		},
		Total: CacheSummary{
			Count:          totalCount,
			TotalSize:      utils.FormatSize(totalSize),
			TotalSizeBytes: totalSize,
		},
	}
}

// 生成完整报告
func generateFullCacheReport(filterProvider string, filterTvgId string) CacheReport {
	report := CacheReport{
		Providers: make(map[string]map[string]CacheReportItem),
	}
	if filterTvgId != "" {
		val, ok := PROVIDER_BY_TVG_ID.Load(filterTvgId)
		if !ok {
			return report
		}
		filterProvider = val.(string)
	}

	if filterTvgId != "" {
		if _, ok := CONFIGS_BY_PROVIDER[filterProvider]; !ok {
			return report
		}
	}

	// 遍历所有 provider
	for provider := range CONFIGS_BY_PROVIDER {
		if filterProvider != "" && filterProvider != provider {
			continue
		}

		report.Providers[provider] = make(map[string]CacheReportItem)

		manifestReports := generateProviderCacheReport(MANIFEST_CACHE_BY_PROVIDER[provider])
		segmentReports := generateProviderCacheReport(SEGMENT_CACHE_BY_PROVIDER[provider])

		// 遍历 tvgId
		tvgSet := make(map[string]struct{})
		for tvgId := range manifestReports {
			tvgSet[tvgId] = struct{}{}
		}
		for tvgId := range segmentReports {
			tvgSet[tvgId] = struct{}{}
		}

		for tvgId := range tvgSet {
			if filterTvgId != "" && tvgId != filterTvgId {
				continue
			}
			mr, ok := manifestReports[tvgId]
			if !ok {
				mr = CacheReportItem{}
			}
			sr, ok := segmentReports[tvgId]
			if !ok {
				sr = CacheReportItem{}
			}
			merged := mergeReportItems(mr, sr)
			report.Providers[provider][tvgId] = merged
		}
	}

	// 生成 total
	var allItems []CacheReportItem
	for _, providerMap := range report.Providers {
		for _, r := range providerMap {
			allItems = append(allItems, r)
		}
	}
	report.Total = mergeReportItems(allItems...)
	return report
}

func CacheStatsHandler(ctx *fasthttp.RequestCtx) {
	provider := string(ctx.QueryArgs().Peek("provider"))
	tvgID := string(ctx.QueryArgs().Peek("tvgId"))

	var report CacheReport
	switch {
	case tvgID != "":
		// 根据 tvgId 找 provider
		p, ok := PROVIDER_BY_TVG_ID.Load(tvgID)
		if !ok {
			ctx.SetStatusCode(404)
			fmt.Fprintf(ctx, "tvgId not found")
			return
		}
		prov := p.(string)
		fullReport := generateFullCacheReport(provider, tvgID)
		items, ok := fullReport.Providers[prov]
		if !ok {
			break
		}
		item, ok := items[tvgID]
		if !ok {
			break
		}
		report.Providers = map[string]map[string]CacheReportItem{
			prov: {tvgID: item},
		}
		report.Total = item

	case provider != "":
		fullReport := generateFullCacheReport(provider, tvgID)
		items, ok := fullReport.Providers[provider]
		if !ok {
			break
		}
		report.Providers = map[string]map[string]CacheReportItem{
			provider: items,
		}
		// 合并 provider 下所有 tvgId 的总量
		var allItems []CacheReportItem
		for _, r := range items {
			allItems = append(allItems, r)
		}
		report.Total = mergeReportItems(allItems...)

	default:
		// 全量统计
		report = generateFullCacheReport(provider, tvgID)
	}

	data, _ := json.MarshalIndent(report, "", "  ")
	ctx.SetContentType("application/json")
	ctx.SetStatusCode(200)
	ctx.SetBody(data)
}
