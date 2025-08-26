package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/edgeware/mp4ff/mp4"
)

// 示例 AES-128 ClearKey（16字节）
var contentKey = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

func main() {
	http.HandleFunc("/proxy/playlist.m3u8", playlistHandler)
	http.HandleFunc("/proxy/", segmentHandler)

	fmt.Println("代理启动: http://localhost:8080/proxy/playlist.m3u8")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// 1️⃣ m3u8 重写，去掉 DRM 并改写分片 URL
func playlistHandler(w http.ResponseWriter, r *http.Request) {
	upstream := "https://example.com/live/playlist.m3u8"
	resp, err := http.Get(upstream)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	lines := strings.Split(string(data), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.HasPrefix(line, "#EXT-X-KEY") {
			continue
		}
		if strings.HasSuffix(line, ".m4s") {
			line = "/proxy/" + strings.TrimPrefix(line, "/live/")
		}
		newLines = append(newLines, line)
	}

	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Write([]byte(strings.Join(newLines, "\n")))
}

// 2️⃣ 分片解密代理
func segmentHandler(w http.ResponseWriter, r *http.Request) {
	upstream := "https://example.com/live/" + strings.TrimPrefix(r.URL.Path, "/proxy/")
	resp, err := http.Get(upstream)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	cipherData, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 解析 MP4
	reader := mp4.NewReaderFromBytes(cipherData)
	f, err := reader.Read()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	// 遍历 track
	for _, trak := range f.Moov.Traks {
		// 只处理视频 track (示例)
		if trak.Mdia.Hdlr.HandlerType != "vide" {
			continue
		}

		// 遍历 traf -> trun -> sample
		for _, traf := range trak.Mdia.Minf.Stbl.Stsd.Avc1.Samples { // 简化示例
			// 示例: 每个 sample 偏移 + IV
			iv := make([]byte, 16) // 实际从 senc box 获取
			data := traf.Data         // 需要解密的字节段
			block, _ := aes.NewCipher(contentKey)
			stream := cipher.NewCTR(block, iv)
			stream.XORKeyStream(data, data)
			traf.Data = data
		}
	}

	// 写回 HTTP
	w.Header().Set("Content-Type", "video/iso.segment")
	w.Write(reader.Bytes()) // 返回解密后的分片
}
