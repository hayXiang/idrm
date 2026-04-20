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
	Token     string
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
func (v *VisitTracker) RecordVisit(tvgID, ip, token, url, streamID string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	key := "tvg:" + tvgID

	var records []VisitRecord
	if x, found := v.cache.Get(key); found {
		records = x.([]VisitRecord)
	}

	records = append(records, VisitRecord{
		IP:        ip,
		Token:     token,
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

// OnlineUser 在线用户信息
type OnlineUser struct {
	IP        string    `json:"ip"`
	Token     string    `json:"token"`
	TvgID     string    `json:"tvgId"`
	URL       string    `json:"url"`
	StreamID  string    `json:"streamId"`
	Timestamp time.Time `json:"timestamp"`
}

// GetAllOnlineUsers 获取所有在线用户
func (v *VisitTracker) GetAllOnlineUsers() []OnlineUser {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var onlineUsers []OnlineUser
	now := time.Now()

	for key, x := range v.cache.Items() {
		if records, ok := x.Object.([]VisitRecord); ok {
			// 从 key 中提取 tvgID
			tvgID := ""
			if len(key) > 4 && key[:4] == "tvg:" {
				tvgID = key[4:]
			}
			for _, r := range records {
				// 只返回30秒内的记录
				if now.Sub(r.Timestamp) <= 30*time.Second {
					onlineUsers = append(onlineUsers, OnlineUser{
						IP:        r.IP,
						Token:     r.Token,
						TvgID:     tvgID,
						URL:       r.URL,
						StreamID:  r.StreamID,
						Timestamp: r.Timestamp,
					})
				}
			}
		}
	}
	return onlineUsers
}
