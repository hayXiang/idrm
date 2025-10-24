package main

import (
	"sync"
	"time"

	"github.com/patrickmn/go-cache"
)

type VisitTracker struct {
	mu    sync.RWMutex
	cache *cache.Cache
}

type VisitRecord struct {
	IP        string
	URL       string
	StreamID  string
	Timestamp time.Time
}

func NewVisitTracker() *VisitTracker {
	return &VisitTracker{
		cache: cache.New(30*time.Second, 1*time.Minute), // 过期30秒
	}
}

// 记录访问
func (v *VisitTracker) RecordVisit(tvgID, ip, url, streamID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := "tvg:" + tvgID

	var records []VisitRecord
	if x, found := v.cache.Get(key); found {
		records = x.([]VisitRecord)
	}

	records = append(records, VisitRecord{
		IP:        ip,
		URL:       url,
		StreamID:  streamID,
		Timestamp: time.Now(),
	})

	v.cache.Set(key, records, cache.DefaultExpiration)
}

// 获取最近30秒的所有访问
func (v *VisitTracker) GetRecentURLs(tvgID string) map[string]VisitRecord {
	v.mu.RLock()
	defer v.mu.RUnlock()

	key := "tvg:" + tvgID
	result := make(map[string]VisitRecord)

	if x, found := v.cache.Get(key); found {
		records := x.([]VisitRecord)
		for _, r := range records {
			if time.Since(r.Timestamp) <= 30*time.Second {
				result[r.IP] = r
			}
		}
	}
	return result
}
