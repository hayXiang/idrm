package main

import "sync"

type RequestManager struct {
	mu       sync.Mutex
	inFlight map[string]chan struct{}
}

func NewRequestManager() *RequestManager {
	return &RequestManager{
		inFlight: make(map[string]chan struct{}),
	}
}

// TryRequest 尝试获取资源
// 返回 true 表示你可以发起请求
// 返回 false 表示已有请求在进行
func (rm *RequestManager) TryRequest(key string) (canRequest bool, waitCh chan struct{}) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if ch, ok := rm.inFlight[key]; ok {
		// 已经有请求在进行，返回等待 channel
		return false, ch
	}

	// 没有请求，可以发起
	ch := make(chan struct{})
	rm.inFlight[key] = ch
	return true, ch
}

// DoneRequest 请求完成，通知等待者
func (rm *RequestManager) DoneRequest(key string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if ch, ok := rm.inFlight[key]; ok {
		close(ch)                // 通知等待者
		delete(rm.inFlight, key) // 删除记录
	}
}
