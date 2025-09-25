package ts

import (
	"crypto/cipher"
	"idrm/utils"
)

var AC3_FRAME_SZIE_TABLE = [38][3]int{
	{64, 69, 96},       // 0
	{64, 70, 96},       // 1
	{80, 87, 120},      // 2
	{80, 88, 120},      // 3
	{96, 104, 144},     // 4
	{96, 105, 144},     // 5
	{112, 121, 168},    // 6
	{112, 122, 168},    // 7
	{128, 139, 192},    // 8
	{128, 140, 192},    // 9
	{160, 174, 240},    // 10
	{160, 175, 240},    // 11
	{192, 208, 288},    // 12
	{192, 209, 288},    // 13
	{224, 243, 336},    // 14
	{224, 244, 336},    // 15
	{256, 278, 384},    // 16
	{256, 279, 384},    // 17
	{320, 348, 480},    // 18
	{320, 349, 480},    // 19
	{384, 417, 576},    // 20
	{384, 418, 576},    // 21
	{448, 487, 672},    // 22
	{448, 488, 672},    // 23
	{512, 557, 768},    // 24
	{512, 558, 768},    // 25
	{576, 626, 864},    // 26
	{576, 627, 864},    // 27
	{640, 696, 960},    // 28
	{640, 697, 960},    // 29
	{768, 835, 1152},   // 30
	{768, 836, 1152},   // 31
	{896, 975, 1344},   // 32
	{896, 976, 1344},   // 33
	{1024, 1114, 1536}, // 34
	{1024, 1115, 1536}, // 35
	{1152, 1253, 1728}, // 36
	{1152, 1254, 1728}, // 37
}

type AudioFrame struct {
	PID      int      // TS 流的 PID
	Payloads [][]byte // 跨 TS 包累积的 ES 数据片段
}

func findAudioNextHeaderAcrossTS(streamType byte, payloads [][]byte, startIdx, startPos int, twoFrameCheck bool) (firstPayloadIdx, firstPos int,
	headerLen, frameLen int,
	nextPayloadIdx, nextPos int,
	ok bool,
) {
	if streamType == STREAM_TYPE_AUDIO_AAC_ADTS {
		return findNextADTSHeaderAcrossTS(payloads, startIdx, startPos, twoFrameCheck)
	} else {
		return findNextAC3HeaderAcrossTS(payloads, startIdx, startPos, twoFrameCheck)
	}
}

func findNextAC3HeaderAcrossTS(payloads [][]byte, startIdx, startPos int, twoFrameCheck bool) (firstPayloadIdx, firstPos int,
	headerLen, frameLen int,
	nextPayloadIdx, nextPos int,
	ok bool) {
	return -1, -1, -1, -1, -1, -1, false
}

func isValidADTSHeaderStrict(header []byte) bool {
	if len(header) < 7 {
		return false
	}
	// syncword
	if header[0] != 0xFF || (header[1]&0xF0) != 0xF0 {
		return false
	}
	// MPEG version (ID)
	id := (header[1] >> 3) & 0x01
	if id != 0 && id != 1 {
		return false
	}
	// Layer 固定为 00
	if (header[1]>>1)&0x03 != 0 {
		return false
	}
	// Profile (AAC object type)
	profile := (header[2] >> 6) & 0x03
	if profile == 3 {
		return false
	}
	// Sampling freq
	sampleIdx := (header[2] >> 2) & 0x0F
	if sampleIdx > 12 {
		return false
	}
	// Channel cfg
	channelCfg := ((header[2]&0x01)<<2 | (header[3] >> 6)) & 0x07
	if channelCfg == 0 || channelCfg > 7 {
		return false
	}
	// Frame length
	frameLen := int((uint16(header[3]&0x03) << 11) |
		(uint16(header[4]) << 3) |
		(uint16(header[5]) >> 5))
	if frameLen < 7 || frameLen > 8191 {
		return false
	}
	return true
}

// findNextADTSHeaderAcrossTS 查找 ADTS header
// twoFrameCheck: 是否开启双帧检测
func findNextADTSHeaderAcrossTS(payloads [][]byte, startIdx, startPos int, twoFrameCheck bool) (
	firstPayloadIdx, firstPos int,
	headerLen, frameLen int,
	nextPayloadIdx, nextPos int,
	ok bool,
) {
	if startIdx < 0 || startIdx >= len(payloads) {
		return -1, -1, 0, 0, -1, -1, false
	}

	var buf [16]byte

	for i := startIdx; i < len(payloads); i++ {
		data := payloads[i]
		p := 0
		if i == startIdx {
			p = startPos
			if p >= len(data) {
				continue
			}
		}

		for p < len(data) {
			if data[p] != 0xFF {
				p++
				continue
			}

			header := getADTSHeader(payloads, i, p, buf[:])
			if header == nil || !isValidADTSHeaderStrict(header) {
				p++
				continue
			}

			hLen1, fLen1 := parseADTSLen(header)
			if fLen1 < hLen1 || fLen1 > 8191 {
				p++
				continue
			}

			if !twoFrameCheck {
				// 只返回第一帧，不做双帧验证
				nextIdx, nextPos := advancePos(payloads, i, p, fLen1)
				return i, p, hLen1, fLen1, nextIdx, nextPos, true
			}

			// ---- 两帧检测 ----
			nextIdx, nextPos := advancePos(payloads, i, p, fLen1)
			if nextIdx == -1 {
				p++
				continue
			}
			header2 := getADTSHeader(payloads, nextIdx, nextPos, buf[:])
			if header2 != nil && isValidADTSHeaderStrict(header2) {
				hLen2, fLen2 := parseADTSLen(header2)
				if fLen2 >= hLen2 && fLen2 <= 8191 {
					return i, p, hLen1, fLen1, nextIdx, nextPos, true
				}
			}

			p++
		}
	}

	return -1, -1, 0, 0, -1, -1, false
}

// advancePos 计算跨 payload 下一帧位置
func advancePos(payloads [][]byte, idx, pos, frameLen int) (nextIdx, nextPos int) {
	remain := frameLen
	nextIdx, nextPos = idx, pos
	for remain > 0 && nextIdx < len(payloads) {
		data := payloads[nextIdx]
		avail := len(data) - nextPos
		if remain <= avail {
			nextPos += remain
			return nextIdx, nextPos
		}
		remain -= avail
		nextIdx++
		nextPos = 0
	}
	return -1, -1
}

// getADTSHeader 跨 payload 获取 header
func getADTSHeader(payloads [][]byte, idx, pos int, buf []byte) []byte {
	data := payloads[idx]
	if len(data)-pos >= 7 {
		return data[pos : pos+7]
	}
	n := copy(buf, data[pos:])
	bytesNeeded := 7 - n
	idx++
	for bytesNeeded > 0 && idx < len(payloads) {
		toCopy := len(payloads[idx])
		if toCopy > bytesNeeded {
			toCopy = bytesNeeded
		}
		n += copy(buf[n:], payloads[idx][:toCopy])
		bytesNeeded -= toCopy
		idx++
	}
	if n < 7 {
		return nil
	}
	return buf[:7]
}

// parseADTSLen 解析 headerLen / frameLen
func parseADTSLen(header []byte) (headerLen, frameLen int) {
	prot := header[1] & 0x01
	headerLen = 7
	if prot == 0 {
		headerLen = 9
	}
	frameLen = int((uint16(header[3]&0x03) << 11) |
		(uint16(header[4]) << 3) |
		(uint16(header[5]&0xE0) >> 5))
	return
}

func (audioFrame *AudioFrame) Process(block cipher.Block, ts *TSPacket, iv []byte, streamType byte, packageIndex int) {
	isEnd := ts == nil
	if !isEnd {
		if ts.PES == nil || len(ts.PES.ES) == 0 {
			return
		}
		audioFrame.Payloads = append(audioFrame.Payloads, ts.PES.ES)
	}

	for {
		startPayloadIdx, startPos, headerLen, _, nextPayloadIdx, nextPos, ok := findAudioNextHeaderAcrossTS(streamType, audioFrame.Payloads, 0, 0, true)
		if !ok {
			if isEnd {
				startPayloadIdx, startPos, headerLen, _, nextPayloadIdx, nextPos, ok = findAudioNextHeaderAcrossTS(streamType, audioFrame.Payloads, 0, 0, false)
			}
			if !ok {
				break
			}
		}

		// 拼接完整 AUDIO 数据
		audioData := []byte{}
		for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
			start := 0
			end := len(audioFrame.Payloads[i])
			if i == startPayloadIdx {
				start = startPos
			}
			if i == nextPayloadIdx {
				end = nextPos
			}
			audioData = append(audioData, audioFrame.Payloads[i][start:end]...)
		}

		if len(audioData) > headerLen+16 {
			utils.DecryptCBCSInPlace(block, audioData[headerLen+16:], iv, 1, 0)

			// 回填原始 Payloads
			offset := 0
			for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
				start := 0
				end := len(audioFrame.Payloads[i])
				if i == startPayloadIdx {
					start = startPos
				}
				if i == nextPayloadIdx {
					end = nextPos
				}
				size := end - start
				copy(audioFrame.Payloads[i][start:end], audioData[offset:offset+size])
				offset += size
			}
		}

		oldPayloads := audioFrame.Payloads
		newPayloads := [][]byte{}

		if nextPayloadIdx < len(oldPayloads) {
			newPayloads = append(newPayloads, oldPayloads[nextPayloadIdx][nextPos:])
		}

		// 后续完整 payloads
		for i := nextPayloadIdx + 1; i < len(oldPayloads); i++ {
			newPayloads = append(newPayloads, oldPayloads[i])
		}
		audioFrame.Payloads = newPayloads
	}
}
