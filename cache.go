package main

import (
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

// 缓存项
type CacheItem struct {
	Data     []byte
	FileType string
}

// 写任务
type fileTask struct {
	key  string
	item CacheItem
}

type FileCache struct {
	memCache  *cache.Cache
	dir       string
	fileTTL   int
	memTTL    int
	mu        sync.RWMutex
	writeChan chan fileTask
	wg        sync.WaitGroup
	stopCh    chan struct{}
}

// NewFileCache 创建文件缓存
// memTTL: 内存缓存默认时间
// fileTTL: 文件缓存默认时间 (如果 fileTTL == -1，则不启用文件缓存)
func NewFileCache(dir string, memTTL int, fileTTL int) *FileCache {
	fc := &FileCache{
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
func (fc *FileCache) writeWorker() {
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
func (fc *FileCache) writeFile(key string, item CacheItem) {
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
	if err := os.WriteFile(tmpMeta, []byte(item.FileType), 0644); err == nil {
		_ = os.Rename(tmpMeta, metaPath)
	}
}

// Set 缓存数据
func (fc *FileCache) Set(key string, data []byte, fileType string) {
	if fc.memTTL < 0 && fc.fileTTL < 0 {
		return
	}

	key = fileNameFromKey(key)
	item := CacheItem{Data: data, FileType: fileType}
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
func (fc *FileCache) Get(key string) ([]byte, string, bool, error) {
	key = fileNameFromKey(key)

	if val, ok := fc.memCache.Get(key); ok {
		item := val.(CacheItem)
		return item.Data, item.FileType, true, nil
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
	fileType, _ := os.ReadFile(metaPath)

	item := CacheItem{Data: data, FileType: string(fileType)}
	if fc.memTTL >= 0 {
		fc.memCache.Set(key, item, time.Duration(fc.memTTL)*time.Second)
	}
	return item.Data, item.FileType, true, nil
}

// Delete 删除缓存
func (fc *FileCache) Delete(key string) {
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
func (fc *FileCache) cleanupLoop() {
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
func (fc *FileCache) Close() {
	close(fc.stopCh)
	fc.wg.Wait()
}
