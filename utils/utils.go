package utils

import (
	"fmt"
	"time"	
)
func FormatSize(size int64) string {
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

func FormatDuration(d time.Duration) string {
	ms := d.Milliseconds() // 转换为毫秒
	sec := d.Seconds()     // 转换为秒

	if ms >= 1000 {
		return fmt.Sprintf("%.2f s", sec) // 大于等于 1 秒显示秒
	}
	return fmt.Sprintf("%d ms", ms) // 小于 1 秒显示毫秒
}
