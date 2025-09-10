package main

import (
	"log"
	"sync"
	"time"

	"github.com/valyala/fasthttp"
)

type HLSUpdater struct {
	provider   string
	tvgID      string
	mpdURL     string
	interval   time.Duration
	stopCh     chan struct{}
	lastAccess time.Time
	client     *fasthttp.Client
	headers    []string
}

var (
	updaters   = make(map[string]*HLSUpdater)
	updatersMu sync.Mutex
)

func startOrResetUpdater(provider, tvgID, mpdURL string, client *fasthttp.Client, headers []string, interval time.Duration) {
	updatersMu.Lock()
	defer updatersMu.Unlock()

	upd, exists := updaters[tvgID]
	if exists {
		// 重置访问时间
		upd.lastAccess = time.Now()
		return
	}

	// 创建新的 updater
	upd = &HLSUpdater{
		provider:   provider,
		tvgID:      tvgID,
		mpdURL:     mpdURL,
		interval:   interval,
		stopCh:     make(chan struct{}),
		lastAccess: time.Now(),
		client:     client,
		headers:    headers,
	}

	updaters[tvgID] = upd

	go func(u *HLSUpdater) {
		ticker := time.NewTicker(u.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// 检查是否超时
				if time.Since(u.lastAccess) > 30*time.Second {
					log.Println("Stopping updater for", u.tvgID)
					updatersMu.Lock()
					delete(updaters, u.tvgID)
					updatersMu.Unlock()
					return
				}

				_, resp, err := fetchWithRedirect(u.client, u.mpdURL, 5, u.headers)
				if err != nil || resp.StatusCode() != fasthttp.StatusOK {
					log.Printf("[ERROR] 更新mpd失败%s，%s, %v", u.tvgID, u.mpdURL, err)
					continue
				}
				defer fasthttp.ReleaseResponse(resp)
				body, err := modifyMpd(provider, u.tvgID, u.mpdURL, resp.Body())
				if err != nil {
					log.Printf("[ERROR]  重写mpd错误 %s，%s, %s", u.tvgID, u.mpdURL, err)
					continue
				}
				hlsMap, _ := DashToHLS(u.mpdURL, body, u.tvgID)
				hlsByTvgId.Store(u.tvgID, hlsMap)
				log.Println("Updated HLS for", u.tvgID)

			case <-u.stopCh:
				log.Println("Updater stopped manually for", u.tvgID)
				return
			}
		}
	}(upd)
}