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
	mpdURL      string
	interval    time.Duration
	stopCh      chan struct{}
	lastAccess  time.Time
	client      *fasthttp.Client
	headers     []string
	httpTimeout int
}

var (
	updaters   = make(map[string]*HLSUpdater)
	updatersMu sync.Mutex
)

func startOrResetUpdater(provider, tvgID, mpdURL string, client *fasthttp.Client, headers []string, interval time.Duration, timeout int) {
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
		provider:    provider,
		tvgID:       tvgID,
		mpdURL:      mpdURL,
		interval:    interval,
		stopCh:      make(chan struct{}),
		lastAccess:  time.Now(),
		client:      client,
		headers:     headers,
		httpTimeout: timeout,
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

				_, resp, err := fetchWithRedirect(u.client, u.mpdURL, 5, u.headers, u.httpTimeout)
				if err != nil || resp.StatusCode() != fasthttp.StatusOK {
					log.Printf("[ERROR] 更新mpd失败%s，%s, %v", u.tvgID, u.mpdURL, err)
					continue
				}
				fasthttp.ReleaseResponse(resp)
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

// 返回 HLS playlists 内容，key = filename, value = m3u8 内容
func DashToHLS(mpdUrl string, body []byte, tvgId string) (map[string]string, error) {
	doc := etree.NewDocument()
	hlsMap := make(map[string]string)
	hlsMap["mpd"] = mpdUrl

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
			mediaBuilder.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n#EXT-X-TARGETDURATION:6\n")

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
