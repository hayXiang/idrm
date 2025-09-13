package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beevik/etree"
	"github.com/valyala/fasthttp"
)

type HLSUpdater struct {
	provider    string
	tvgID       string
	mainfestUrl string
	interval    time.Duration
	stopCh      chan struct{}
	lastAccess  time.Time
	client      *fasthttp.Client
	config      *StreamConfig
}

var updaters sync.Map

func startOrResetUpdater(provider, tvgID, mainfestUrl string, client *fasthttp.Client, config *StreamConfig, interval time.Duration) {
	cachedUpd, exists := updaters.Load(tvgID)
	if exists {
		cachedUpd.(*HLSUpdater).lastAccess = time.Now()
		return
	}

	// 创建新的 updater
	upd := &HLSUpdater{
		provider:    provider,
		tvgID:       tvgID,
		mainfestUrl: mainfestUrl,
		interval:    interval,
		stopCh:      make(chan struct{}),
		lastAccess:  time.Now(),
		client:      client,
		config:      config,
	}

	updaters.Store(tvgID, upd)

	go func(u *HLSUpdater) {
		update := func() {
			// 检查是否超时
			if time.Since(u.lastAccess) > 30*time.Second {
				close(u.stopCh)
				updaters.Delete(u.tvgID)
				return
			}

			finalURI, resp, err := fetchWithRedirect(u.client, u.mainfestUrl, 5, u.config.Headers, *u.config.HttpTimeout)
			if err != nil || resp.StatusCode() != fasthttp.StatusOK {
				log.Printf("[ERROR] 更新manifest失败 %s，%s, %v", u.tvgID, u.mainfestUrl, err)
				return
			}
			body := append([]byte(nil), resp.Body()...)
			contentType := string(resp.Header.ContentType())
			fasthttp.ReleaseResponse(resp)

			var hlsMap = make(map[string]string)
			var hlsMapLock sync.Mutex

			if strings.Contains(u.mainfestUrl, ".mpd") || contentType == "application/dash+xml" {
				body, err = modifyMpd(u.provider, u.tvgID, u.mainfestUrl, body)
				if err != nil {
					log.Printf("[ERROR]  重写mpd错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				hlsMap, err = DashToHLS(u.mainfestUrl, body, u.tvgID)
				if err != nil {
					log.Printf("[ERROR]  Dash TO HLS错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				hlsByTvgId.Store(u.tvgID, hlsMap)
			} else {
				body = modifyHLS(body, u.tvgID, u.mainfestUrl, *u.config.BestQuality)
				urls, err := HLSParse(body, finalURI)
				if err != nil {
					log.Printf("[ERROR] HLS解析错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				var wg sync.WaitGroup
				for key, url := range urls {
					wg.Add(1)
					go func(_key, _url string) {
						defer wg.Done()
						_, resp, err := fetchWithRedirect(u.client, _url, 5, u.config.Headers, *u.config.HttpTimeout)
						if err != nil {
							fmt.Println("请求失败:", _url, err)
							return
						}
						modifyBody := modifyHLS(resp.Body(), u.tvgID, _url, *u.config.BestQuality)
						hlsMapLock.Lock()
						hlsMap[_key+".m3u8"] = string(modifyBody)
						hlsMapLock.Unlock()
						fasthttp.ReleaseResponse(resp)
					}(key, url)
				}
				wg.Wait()
			}

			log.Println("Updated HLS for", u.tvgID)

			// 预加载最后三个分片
			for name, playlist := range hlsMap {
				if name == "master.m3u8" || !strings.HasSuffix(name, ".m3u8") {
					continue
				}
				var segmentList []string
				playlist = strings.ReplaceAll(playlist, "#EXT-X-MAP:URI=\"", "")
				lines := strings.Split(playlist, "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					segmentList = append(segmentList, line)
				}

				lastSegments := segmentList
				if len(segmentList) > 3 {
					lastSegments = segmentList[len(segmentList)-3:]
				}
				preloadSegments(u.provider, u.tvgID, lastSegments)
			}
		}
		update()

		ticker := time.NewTicker(u.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				update() // 后续周期更新仍然异步执行
			case <-u.stopCh:
				log.Println("Updater stopped manually for", u.tvgID)
				return
			}
		}
	}(upd)
}

func GetMaxSegmentDuration(adp *etree.Element) float64 {
	var maxDur float64 = 0
	timescale := 1.0

	for _, segTpl := range adp.FindElements("//SegmentTemplate") {
		tsAttr := segTpl.SelectAttrValue("timescale", "1")
		t, _ := strconv.ParseFloat(tsAttr, 64)
		timescale = t

		timeline := segTpl.SelectElement("SegmentTimeline")
		if timeline != nil {
			for _, s := range timeline.SelectElements("S") {
				dAttr := s.SelectAttrValue("d", "0")
				dur, _ := strconv.ParseFloat(dAttr, 64)
				segDur := dur / timescale
				if segDur > maxDur {
					maxDur = segDur
				}
			}
		} else {
			// fallback: 单个 duration
			durAttr := segTpl.SelectAttrValue("duration", "")
			if durAttr != "" {
				dur, _ := strconv.ParseFloat(durAttr, 64)
				segDur := dur / timescale
				if segDur > maxDur {
					maxDur = segDur
				}
			}
		}
	}
	return maxDur
}

// 返回 HLS playlists 内容，key = filename, value = m3u8 内容
func DashToHLS(mpdUrl string, body []byte, tvgId string) (map[string]string, error) {
	doc := etree.NewDocument()
	hlsMap := make(map[string]string)

	var masterBuilder strings.Builder
	masterBuilder.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n")

	if err := doc.ReadFromBytes(body); err != nil {
		return nil, fmt.Errorf("failed to parse MPD: %v", err)
	}

	periods := doc.FindElements("//MPD/Period")
	for _, period := range periods {
		subtitleExists := periodHasSubtitle(period)
		adaps := period.FindElements("AdaptationSet")

		for _, adap := range adaps {
			maxDuration := int(GetMaxSegmentDuration(adap))
			contentType := adap.SelectAttrValue("contentType", "")
			groupID := contentType

			rep := adap.FindElement("Representation")
			if rep == nil {
				continue
			}
			repID := rep.SelectAttrValue("id", "")
			bandwidth := rep.SelectAttrValue("bandwidth", "")
			codecs := rep.SelectAttrValue("codecs", "")
			resolution := ""
			if contentType == "video" {
				width := rep.SelectAttrValue("width", "")
				height := rep.SelectAttrValue("height", "")
				resolution = fmt.Sprintf("%sx%s", width, height)
			}

			playlistName := fmt.Sprintf("%s_%s.m3u8", contentType, repID)

			switch contentType {
			case "text", "subtitle":
				lang := adap.SelectAttrValue("lang", "und")
				masterBuilder.WriteString(fmt.Sprintf(
					`#EXT-X-MEDIA:TYPE=SUBTITLES,GROUP-ID="subs",LANGUAGE="%s",NAME="%s",AUTOSELECT=YES,DEFAULT=NO,FORCED=NO,URI="/drm/proxy/hls/%s/%s"`+"\n",
					lang, lang, tvgId, playlistName))
			case "audio":
				lang := adap.SelectAttrValue("lang", "und")
				masterBuilder.WriteString(fmt.Sprintf(
					`#EXT-X-MEDIA:TYPE=AUDIO,GROUP-ID="%s",LANGUAGE="%s",NAME="%s",AUTOSELECT=YES,DEFAULT=YES,URI="/drm/proxy/hls/%s/%s"`+"\n",
					groupID, lang, lang, tvgId, playlistName))
			default:
				line := fmt.Sprintf(`#EXT-X-STREAM-INF:BANDWIDTH=%s,RESOLUTION=%s,CODECS="%s",AUDIO="audio"`,
					bandwidth, resolution, codecs)
				if subtitleExists {
					line += `,SUBTITLES="subs"`
				}
				masterBuilder.WriteString(line + "\n")
				masterBuilder.WriteString(fmt.Sprintf("/drm/proxy/hls/%s/%s\n", tvgId, playlistName))
			}

			// 生成 media playlist
			var mediaBuilder strings.Builder
			mediaBuilder.WriteString(fmt.Sprintf("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:%d\n", maxDuration))

			segTemp := adap.FindElement("SegmentTemplate")
			if segTemp == nil {
				continue
			}
			startNumber, _ := strconv.Atoi(segTemp.SelectAttrValue("startNumber", "1"))
			timescale, _ := strconv.Atoi(segTemp.SelectAttrValue("timescale", "1"))
			mediaTemplate := strings.ReplaceAll(segTemp.SelectAttrValue("media", ""), "$RepresentationID$", repID)
			initURI := strings.ReplaceAll(segTemp.SelectAttrValue("initialization", ""), "$RepresentationID$", repID)

			mediaBuilder.WriteString(fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", startNumber))
			mediaBuilder.WriteString(fmt.Sprintf(`#EXT-X-MAP:URI="%s"`+"\n", initURI))

			timeline := segTemp.FindElement("SegmentTimeline")
			if timeline != nil {
				seq := startNumber
				lastT := 0
				for _, s := range timeline.FindElements("S") {
					d, _ := strconv.Atoi(s.SelectAttrValue("d", "0"))
					r, _ := strconv.Atoi(s.SelectAttrValue("r", "0"))
					tStr := s.SelectAttrValue("t", "")
					t := 0
					if tStr != "" {
						t, _ = strconv.Atoi(tStr)
					} else {
						t = lastT
					}
					duration := float64(d) / float64(timescale)

					for i := 0; i <= r; i++ {
						segURI := strings.ReplaceAll(mediaTemplate, "$Time$", strconv.Itoa(t))
						mediaBuilder.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n%s\n", duration, segURI))
						t += d
						seq++
					}
					lastT = t
				}
			}

			hlsMap[playlistName] = mediaBuilder.String()
		}
	}

	hlsMap["master.m3u8"] = masterBuilder.String()
	return hlsMap, nil
}

func preloadSegments(provider string, tvgID string, segmentURLs []string) {
	cache := segmentCacheByProvider[provider]
	client := clientsByProvider[provider]
	config := configsByProvider[provider]
	for _, segURL := range segmentURLs {
		segURL = strings.Replace(segURL, "/drm/proxy/m4s/"+tvgID, "", 1)
		segURL = strings.Replace(segURL, "/http/", "http://", 1)
		segURL = strings.Replace(segURL, "/https/", "https://", 1)

		// 先看缓存
		if data, _, _, _ := cache.Get(segURL); data != nil {
			//log.Printf("资源Hit(预加载）： %s，%s", tvgID, segURL)
			continue
		}

		if canRequest, _ := rm.TryRequest(segURL); canRequest {
			go func(url string) {
				defer func() {
					rm.DoneRequest(url)
					log.Printf("预加载结束：%s, %s，%s", "preloader", tvgID, url)
				}()
				log.Printf("下载开始(预加载）：%s, %s，%s", "preloader", tvgID, url)
				start := time.Now()
				_, resp, err := fetchWithRedirect(client, url, 5, config.Headers, *config.HttpTimeout)
				log.Printf("下载结束：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, formatDuration(time.Since(start)))
				if err != nil {
					return
				}
				defer fasthttp.ReleaseResponse(resp)
				body, err := fetchAndDecryptWidevineBody(client, config, tvgID, url, resp.Body(), nil)
				if err != nil {
					return
				}
				if cache != nil {
					cache.Set(url, body, "application/octet-stream")
				}
			}(segURL)
		}
	}
}

func HLSParse(body []byte, baseURL string) (map[string]string, error) {
	lines := strings.Split(string(body), "\n")
	result := make(map[string]string)

	var lastStreamInfo string
	var streamCount, audioCount, subCount int

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#EXTM3U") {
			continue
		}

		// 多码率流
		if strings.HasPrefix(line, "#EXT-X-STREAM-INF:") {
			lastStreamInfo = line
			continue
		}

		// STREAM-INF 对应的下一行是 URI
		if lastStreamInfo != "" && !strings.HasPrefix(line, "#") {
			streamCount++
			key := fmt.Sprintf("stream-%d", streamCount)
			result[key] = resolveURL(line, baseURL)
			lastStreamInfo = ""
			continue
		}

		// 音轨/字幕
		if strings.HasPrefix(line, "#EXT-X-MEDIA:") {
			attrs := parseAttrs(line[len("#EXT-X-MEDIA:"):])
			if uri, ok := attrs["URI"]; ok {
				switch attrs["TYPE"] {
				case "AUDIO":
					audioCount++
					key := fmt.Sprintf("audio-%s", attrs["LANGUAGE"])
					if key == "audio-" || result[key] != "" {
						key = fmt.Sprintf("audio-%d", audioCount)
					}
					result[key] = resolveURL(uri, baseURL)
				case "SUBTITLES":
					subCount++
					key := fmt.Sprintf("subtitle-%s", attrs["LANGUAGE"])
					if key == "subtitle-" || result[key] != "" {
						key = fmt.Sprintf("subtitle-%d", subCount)
					}
					result[key] = resolveURL(uri, baseURL)
				}
			}
		}
	}

	return result, nil
}

func parseAttrs(attrLine string) map[string]string {
	attrs := map[string]string{}
	parts := strings.Split(attrLine, ",")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			key := kv[0]
			val := strings.Trim(kv[1], `"`)
			attrs[key] = val
		}
	}
	return attrs
}
