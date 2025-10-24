package main

import (
	"fmt"
	"idrm/utils"
	"log"
	"math"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Eyevinn/mp4ff/mp4"
	"github.com/beevik/etree"
	"github.com/patrickmn/go-cache"
)

// 全局缓存器（默认保留 30 分钟）
var hlsManager = NewHLSSeqManager()

type HLSUpdater struct {
	provider    string
	tvgID       string
	mainfestUrl string
	interval    time.Duration
	stopCh      chan struct{}
	lastAccess  time.Time
	client      *http.Client
	config      *StreamConfig
	stopOnce    sync.Once
}

var updaters sync.Map

func startOrResetUpdater(provider, tvgID, mainfestUrl string, client *http.Client, config *StreamConfig, interval time.Duration) {
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
				u.stopOnce.Do(func() {
					close(u.stopCh)
					updaters.Delete(u.tvgID)
				})
				return
			}

			_, body, err, contentType, finalURI := HttpGet(u.client, u.mainfestUrl, u.config.Headers)
			if err != nil {
				log.Printf("[ERROR] 更新manifest失败 %s，%s, %v", u.tvgID, u.mainfestUrl, err)
				return
			}
			var hlsMap = make(map[string]string)
			var hlsMapLock sync.Mutex
			var mediaType = "dynamic"
			if strings.Contains(u.mainfestUrl, ".mpd") || contentType == "application/dash+xml" {
				body, err = modifyMpd(u.provider, u.tvgID, finalURI, body)
				if err != nil {
					log.Printf("[ERROR]  重写mpd错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				mediaType, hlsMap, err = DashToHLS(finalURI, body, u.tvgID, *u.config.BestQuality)
				if err != nil {
					log.Printf("[ERROR]  Dash TO HLS错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				HLS_BY_TVG_ID.Store(u.tvgID, hlsMap)
				HLS_TYPE_BY_TVG_ID.Store(u.tvgID, mediaType)
			} else {
				body = modifyHLS(body, u.tvgID, finalURI, *u.config.BestQuality)
				urls, err := HLSParse(body, finalURI)
				if err != nil {
					log.Printf("[ERROR] HLS解析错误 %s，%s, %s", u.tvgID, u.mainfestUrl, err)
					return
				}
				manifestCache := MANIFEST_CACHE_BY_PROVIDER[u.provider]
				var wg sync.WaitGroup
				for key, url := range urls {
					wg.Add(1)
					go func(_key, _url string) {
						defer wg.Done()
						_, body, err, m3u8ContentType, finalURI := HttpGet(u.client, _url, u.config.Headers)
						if err != nil {
							fmt.Println("请求失败:", _url, err)
							return
						}
						modifyBody := modifyHLS(body, u.tvgID, finalURI, *u.config.BestQuality)
						hlsMapLock.Lock()
						m3u8Content := string(modifyBody)
						hlsMap[_key+".m3u8"] = m3u8Content
						if strings.Contains(m3u8Content, "#EXT-X-ENDLIST") {
							HLS_TYPE_BY_TVG_ID.Store(u.tvgID, "static")
						}
						if manifestCache != nil {
							manifestCache.Set(_url, modifyBody, MyMetadata{m3u8ContentType, u.tvgID, 0})
						}
						hlsMapLock.Unlock()
					}(key, url)
				}
				wg.Wait()
			}
			log.Println("Updated HLS for", u.tvgID)
			if !*config.SpeedUp {
				return
			}
			// 预加载三个分片,直播流是最后三个，点播流是最近一分钟用户访问的文件的后三个。
			for name, playlist := range hlsMap {
				if name == "master.m3u8" || !strings.HasSuffix(name, ".m3u8") {
					continue
				}
				var segmentList []string
				var initM4sUrl string = ""
				lines := strings.Split(playlist, "\n")
				for _, line := range lines {
					if strings.HasPrefix(line, "#EXT-X-MAP:") {
						matches := M3U8_INIT_REGEXP.FindStringSubmatch(line)
						if len(matches) == 2 {
							initM4sUrl = matches[1]
						}
					}
					if strings.HasPrefix(line, "#") || line == "" {
						continue
					}
					segmentList = append(segmentList, line)
				}

				if mediaType, ok := HLS_TYPE_BY_TVG_ID.Load(tvgID); ok && mediaType == "static" {
					recent := VISIT_TRACKER.GetRecentURLs(tvgID)
					if len(recent) == 0 {
						lastSegments := segmentList[0:min(3, len(segmentList))]
						preloadSegments(u.provider, u.tvgID, lastSegments, initM4sUrl)
					} else {
						for _, record := range recent {
							//根据url找出后面的segment,按照文件名
							//log.Printf("[最近访问] tvgID=%s IP=%s URL=%s", tvgID, ip, record.URL)
							// 根据 URL 提取文件名
							filename := path.Base(record.URL)

							// 找出该文件在 segmentList 中的位置
							startIdx := -1
							for i, seg := range segmentList {
								if strings.Contains(seg, filename) {
									startIdx = i
									break
								}
							}

							// 如果找到了对应的分片，取后续的 3 个
							if startIdx != -1 {
								nextStart := startIdx + 1
								if nextStart < len(segmentList) {
									end := min(nextStart+3, len(segmentList))
									nextSegments := segmentList[nextStart:end]
									//log.Printf("[预加载] IP=%s 起始=%s 下3片=%v", ip, filename, nextSegments)
									preloadSegments(u.provider, u.tvgID, nextSegments, initM4sUrl)
								}
							}
						}
					}
				} else {
					lastSegments := segmentList
					if len(segmentList) > 3 {
						lastSegments = segmentList[len(segmentList)-3:]
					}
					preloadSegments(u.provider, u.tvgID, lastSegments, initM4sUrl)
				}
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

func GetMaxSegmentDurationInt(adp *etree.Element) int {
	var maxDur float64
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
	return int(math.Ceil(maxDur))
}

// 返回 HLS playlists 内容，key = filename, value = m3u8 内容
func DashToHLS(mpdUrl string, body []byte, tvgId string, bestQuality bool) (string, map[string]string, error) {
	doc := etree.NewDocument()
	hlsMap := make(map[string]string)

	var masterBuilder strings.Builder
	masterBuilder.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-INDEPENDENT-SEGMENTS\n")

	if err := doc.ReadFromBytes(body); err != nil {
		return "", nil, fmt.Errorf("failed to parse MPD: %v", err)
	}

	mpd := doc.FindElement("//MPD")
	if mpd == nil {
		return "", nil, fmt.Errorf("not found MPD")
	}
	media_type := mpd.SelectAttrValue("type", "")
	is_static := media_type == "static"

	periods := doc.FindElements("//MPD/Period")
	for _, period := range periods {
		subtitleExists := periodHasSubtitle(period)
		adaps := period.FindElements("AdaptationSet")

		for _, adap := range adaps {
			maxDuration := GetMaxSegmentDurationInt(adap)
			contentType := adap.SelectAttrValue("contentType", "")
			if contentType == "" {
				mimeType := adap.SelectAttrValue("mimeType", "")
				if strings.HasPrefix(mimeType, "video") {
					contentType = "video"
				} else if strings.HasPrefix(mimeType, "audio") {
					contentType = "audio"
				} else if strings.HasPrefix(mimeType, "text") || strings.HasPrefix(mimeType, "application") {
					contentType = "text"
				}
			}

			if contentType == "" {
				continue
			}
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
			startNumber, _ := strconv.Atoi(segTemp.SelectAttrValue("startNumber", "-1"))
			timescale, _ := strconv.Atoi(segTemp.SelectAttrValue("timescale", "1"))
			mediaTemplate := strings.ReplaceAll(segTemp.SelectAttrValue("media", ""), "$RepresentationID$", repID)

			var segmentBuilder strings.Builder
			timeline := segTemp.FindElement("SegmentTimeline")
			seq := startNumber
			if timeline != nil {
				if seq == -1 {
					newSegTimes := parseTimeline(timeline)
					seq = hlsManager.UpdateTimelineSegments(tvgId+"_"+playlistName, newSegTimes)
					startNumber = seq
				}
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
						segURI = strings.ReplaceAll(segURI, "$Number$", strconv.Itoa(seq))
						segmentBuilder.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n%s\n", duration, segURI))
						t += d
						seq++
					}
					lastT = t
				}
			} else {
				periodDurationStr := mpd.SelectAttrValue("mediaPresentationDuration", "")
				periodDuration := 0.0
				if periodDurationStr != "" {
					periodDuration, _ = parseDuration(periodDurationStr) // ISO 8601 转秒
				}
				peridoDurationTotal := periodDuration * float64(timescale)
				// SegmentTimeline 缺失 -> fallback
				duration, _ := strconv.Atoi(segTemp.SelectAttrValue("duration", "0"))
				durSec := float64(duration) / float64(timescale)
				for peridoDurationTotal > 0 {
					segURI := strings.ReplaceAll(mediaTemplate, "$Number$", strconv.Itoa(seq))
					segDur := durSec
					if peridoDurationTotal < float64(duration) {
						segDur = peridoDurationTotal / float64(timescale)
					}
					segmentBuilder.WriteString(fmt.Sprintf("#EXTINF:%.3f,\n%s\n", segDur, segURI))
					seq++
					peridoDurationTotal -= float64(duration)
				}
			}

			// --------------------
			// 直播，保留最多 10 个分片
			// --------------------
			firstSeq := startNumber
			if !is_static {
				segments := strings.Split(strings.TrimSpace(segmentBuilder.String()), "\n")
				segCount := len(segments) / 2 // 总分片数
				keep := segCount
				if keep > 10 {
					keep = 10
					segments = segments[len(segments)-(keep*2):]
				}
				firstSeq = startNumber + (segCount - keep)
				segmentBuilder.Reset()
				segmentBuilder.WriteString(strings.Join(segments, "\n"))
			}

			if is_static {
				segmentBuilder.WriteString("#EXT-X-ENDLIST")
			}

			initURI := strings.ReplaceAll(segTemp.SelectAttrValue("initialization", ""), "$RepresentationID$", repID)
			mediaBuilder.WriteString(fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", firstSeq))
			mediaBuilder.WriteString(fmt.Sprintf(`#EXT-X-MAP:URI="%s"`+"\n", initURI))
			mediaBuilder.WriteString(segmentBuilder.String())
			hlsMap[playlistName] = mediaBuilder.String()
		}
	}

	if bestQuality {
		hlsMap["master.m3u8"] = filterHighestAV(masterBuilder.String())
	} else {
		hlsMap["master.m3u8"] = masterBuilder.String()
	}
	return media_type, hlsMap, nil
}

func preloadSegments(provider string, tvgID string, segmentURLs []string, initM4sUrl string) {
	cache := SEGMENT_CACHE_BY_PROVIDER[provider]
	client := CLIENTS_BY_PROVIDER[provider]
	config := CONFIGS_BY_PROVIDER[provider]
	//需要先下载initM4s，才能获取到解密需要的信息。
	// 先确保 init.m4s 已下载并解析
	initReaderChan := make(chan struct{})
	if initM4sUrl != "" {
		// 替换成真实 URL
		url := strings.Replace(initM4sUrl, "/drm/proxy/init-m4s/"+tvgID, "", 1)
		stream_uuid := strings.Split(url, "/")[1]
		url = strings.Replace(url, "/"+stream_uuid, "", 1)
		url = strings.Replace(url, "/http/", "http://", 1)
		url = strings.Replace(url, "/https/", "https://", 1)
		_, ok := SINF_BOX_BY_STREAM_ID.Load(stream_uuid)
		if ok {
			close(initReaderChan)
		} else {
			go func() {
				start := time.Now()
				defer func() {
					close(initReaderChan)
					log.Printf("下载结束：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
				}()
				log.Printf("下载错误：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
				_, responseBody, err, contentType, _ := HttpGet(client, url, config.Headers)
				if err != nil {
					log.Printf("init.m4s 下载失败: %v", err)
					return
				}

				body, sinfBox, err := modifyInitM4sFromBody(responseBody)
				if err != nil {
					return
				}
				SINF_BOX_BY_STREAM_ID.Store(stream_uuid, sinfBox)
				if cache != nil {
					cache.Set(url, body, MyMetadata{contentType, tvgID, 0})
				}
			}()
		}
	} else {
		close(initReaderChan)
	}

	for _, segURL := range segmentURLs {
		proxy_type := "m4s"
		if strings.HasPrefix(segURL, "/drm/proxy/ts") {
			proxy_type = "ts"
		}
		segURL = strings.Replace(segURL, "/drm/proxy/"+proxy_type+"/"+tvgID, "", 1)
		stream_uuid := strings.Split(segURL, "/")[1]
		segURL = strings.Replace(segURL, "/"+stream_uuid, "", 1)
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
				_, body, err, contentType, _ := HttpGet(client, url, config.Headers)
				if err != nil {
					log.Printf("下载错误：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
					return
				} else {
					log.Printf("下载结束：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
				}
				<-initReaderChan
				var sinfBox *mp4.SinfBox
				v, ok := SINF_BOX_BY_STREAM_ID.Load(stream_uuid)
				if ok {
					sinfBox = v.(*mp4.SinfBox)
				}
				body, err = fetchAndDecrypt(client, config, tvgID, body, nil, sinfBox, proxy_type)
				if err != nil {
					log.Printf("解密错误：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
					return
				}
				log.Printf("解密结束：%s, %s，%s, 耗时：%s", "preloader", tvgID, url, utils.FormatDuration(time.Since(start)))
				if cache != nil {
					cache.Set(url, body, MyMetadata{contentType, tvgID, 0})
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

var ptReg = regexp.MustCompile(`PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?`)

func parseDuration(d string) (float64, error) {
	// 示例: PT1H2M10.5S -> 3730.5 秒
	m := ptReg.FindStringSubmatch(d)
	if len(m) != 4 {
		return 0, fmt.Errorf("invalid duration: %s", d)
	}
	hours := AtoiOrZero(m[1])
	mins := AtoiOrZero(m[2])
	secs := ParseFloatOrZero(m[3])
	return float64(hours)*3600 + float64(mins)*60 + secs, nil
}

func AtoiOrZero(s string) int {
	if s == "" {
		return 0
	}
	i, _ := strconv.Atoi(s)
	return i
}

func ParseFloatOrZero(s string) float64 {
	if s == "" {
		return 0
	}
	f, _ := strconv.ParseFloat(s, 64)
	return f
}

// SegmentSeqTracker 记录单一路径的时间戳与 sequence 对应关系
type SegmentSeqTracker struct {
	mu       sync.Mutex
	seqMap   map[int64]int // timeline -> sequence
	maxCount int
}

// HLSSeqManager 管理多个 MPD 的分片序列
type HLSSeqManager struct {
	cache *cache.Cache
}

// 创建管理器
func NewHLSSeqManager() *HLSSeqManager {
	return &HLSSeqManager{
		cache: cache.New(10*time.Minute, 20*time.Minute),
	}
}

// 获取或创建 tracker
func (m *HLSSeqManager) getTracker(mpdURL string) *SegmentSeqTracker {
	if v, ok := m.cache.Get(mpdURL); ok {
		return v.(*SegmentSeqTracker)
	}
	t := &SegmentSeqTracker{
		seqMap:   make(map[int64]int),
		maxCount: 100,
	}
	m.cache.Set(mpdURL, t, cache.DefaultExpiration)
	return t
}

// 更新时间线分片，返回 newSegs[0] 对应的 sequence
func (m *HLSSeqManager) UpdateTimelineSegments(key string, newSegs []int64) int {
	tracker := m.getTracker(key)
	return tracker.Update(newSegs)
}

// Update 根据缓存和新的时间线推导 sequence
func (t *SegmentSeqTracker) Update(newSegs []int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()

	if len(newSegs) == 0 {
		return 1
	}

	startSeq := 1
	reset := true

	// 倒序查找新分片中是否有命中缓存的
	for i := len(newSegs) - 1; i >= 0; i-- {
		segT := newSegs[i]
		if oldSeq, ok := t.seqMap[segT]; ok {
			// 推导出 newSegs[0] 的序号
			offset := i
			startSeq = oldSeq - offset
			if startSeq < 1 {
				startSeq = 1
			}
			reset = false
			break
		}
	}

	// 没找到就从 1 开始
	if reset {
		startSeq = 1
	}

	// 更新缓存映射
	seq := startSeq
	for _, segT := range newSegs {
		t.seqMap[segT] = seq
		seq++
	}

	t.trimCache()
	return startSeq
}

// 保留最近 N 个分片
func (t *SegmentSeqTracker) trimCache() {
	if len(t.seqMap) <= t.maxCount {
		return
	}
	toRemove := len(t.seqMap) - t.maxCount
	for k := range t.seqMap {
		delete(t.seqMap, k)
		toRemove--
		if toRemove <= 0 {
			break
		}
	}
}

// 解析 SegmentTimeline 为时间戳列表
func parseTimeline(timeline *etree.Element) []int64 {
	var times []int64
	lastT := int64(0)
	for _, s := range timeline.FindElements("S") {
		d, _ := strconv.ParseInt(s.SelectAttrValue("d", "0"), 10, 64)
		r, _ := strconv.ParseInt(s.SelectAttrValue("r", "0"), 10, 64)
		tStr := s.SelectAttrValue("t", "")
		t := lastT
		if tStr != "" {
			t, _ = strconv.ParseInt(tStr, 10, 64)
		}
		for i := int64(0); i <= r; i++ {
			times = append(times, t)
			t += d
		}
		lastT = t
	}
	return times
}
