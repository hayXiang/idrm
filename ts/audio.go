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

func findAudioNextHeaderAcrossTS(streamType byte, payloads [][]byte, startIdx, startPos int) (int, int, int, int) {
	if streamType == STREAM_TYPE_AUDIO_AAC_ADTS {
		return findNextADTSHeaderAcrossTS(payloads, startIdx, startPos)
	} else {
		return findNextAC3HeaderAcrossTS(payloads, startIdx, startPos)
	}
}

func findNextAC3HeaderAcrossTS(payloads [][]byte, startIdx, startPos int) (int, int, int, int) {
	for i := startIdx; i < len(payloads); i++ {
		data := payloads[i]
		pos := 0
		if i == startIdx {
			pos = startPos
		}
		for pos+5 <= len(data) {
			if data[pos] == 0x0B && data[pos+1] == 0x77 {
				fscod := (data[pos+2] >> 6) & 0x03
				frmsizecod := data[pos+2] & 0x3F // 0–37
				if fscod == 3 || frmsizecod >= 38 {
					pos++
					continue
				}
				frameLen := AC3_FRAME_SZIE_TABLE[frmsizecod][fscod]
				return i, pos, 5, frameLen
			}
			pos++
		}
	}
	return -1, -1, 0, 0
}

// isValidADTSHeaderFast 是一个简化版的 isValidADTSHeader，
// 用于检查一个固定大小的切片（至少7字节）。
// 它避免了重复的长度检查，适用于已知数据足够的情况。
func isValidADTSHeaderFast(header []byte) bool {
	if len(header) < 7 { // 这个检查在调用前应已保证
		return false
	}
	if header[0] != 0xFF || (header[1]&0xF0) != 0xF0 {
		return false
	}
	layer := (header[1] >> 1) & 0x03
	if layer != 0 {
		return false
	}
	sampleIdx := (header[2] >> 2) & 0x0F
	channelCfg := ((header[2]&0x01)<<2 | (header[3] >> 6)) & 0x07
	if sampleIdx >= 13 || channelCfg == 0 || channelCfg > 7 {
		return false
	}
	return true
}

// findNextADTSHeaderAcrossTS 在 payloads 中查找下一个有效的 ADTS header。
// 它从 payloads[startIdx] 的 startPos 位置开始查找。
// 返回值:
// payloadIdx: 找到头部的 payload 索引 (-1 表示未找到)
// pos: 找到头部在该 payload 中的起始位置
// headerLen: ADTS 头部的长度 (7 or 9 bytes)
// frameLen: 整个 ADTS 帧的长度
func findNextADTSHeaderAcrossTS(payloads [][]byte, startIdx, startPos int) (payloadIdx int, pos int, headerLen int, frameLen int) {
	// 如果起始索引无效，则直接返回未找到
	if startIdx < 0 || startIdx >= len(payloads) {
		return -1, -1, 0, 0
	}

	// 用于跨 payload 检查时拼接数据的小 buffer
	var buf [16]byte // 7字节header + 一些额外空间以确保安全

	for i := startIdx; i < len(payloads); i++ {
		data := payloads[i]
		p := 0
		// 对于起始 payload，从指定的 startPos 开始
		if i == startIdx {
			p = startPos
			// 如果起始位置就无效，则跳到下一个 payload
			if p >= len(data) {
				continue
			}
		}

		// 遍历当前 payload 中的字节
		for p < len(data) {
			// 快速跳过明显不是同步字开头的字节，提高效率
			if data[p] != 0xFF {
				p++
				continue
			}

			var headerData []byte

			// 情况 1: 当前 payload 剩余字节足够容纳一个 ADTS header
			if len(data)-p >= 7 {
				headerData = data[p : p+7]
			} else {
				// 情况 2: header 跨越了当前 payload 和后续 payload
				// 计算需要从后续 payload 拿多少字节
				bytesNeeded := 7 - (len(data) - p)
				n := copy(buf[:], data[p:]) // 先复制当前 payload 剩余部分

				// 从后续 payloads 中复制所需字节
				payloadIdxForCopy := i + 1
				for bytesNeeded > 0 && payloadIdxForCopy < len(payloads) {
					bytesToCopy := len(payloads[payloadIdxForCopy])
					if bytesToCopy > bytesNeeded {
						bytesToCopy = bytesNeeded
					}
					n += copy(buf[n:], payloads[payloadIdxForCopy][:bytesToCopy])
					bytesNeeded -= bytesToCopy
					payloadIdxForCopy++
				}

				// 如果拼接后的数据不足 7 字节，则无法构成 header
				if n < 7 {
					// 移动到下一个可能的同步字位置
					p++
					continue
				}
				headerData = buf[:7]
			}

			// 使用快速验证函数检查拼接后的数据是否为有效 header
			if isValidADTSHeaderFast(headerData) {
				// 提取 header 长度和帧长度
				prot := headerData[1] & 0x01
				hLen := 7
				if prot == 0 {
					hLen = 9
				}
				fLen := int((uint16(headerData[3]&0x03) << 11) |
					(uint16(headerData[4]) << 3) |
					(uint16(headerData[5]&0xE0) >> 5))

				// 最终验证帧长度是否合理
				if fLen >= hLen {
					return i, p, hLen, fLen
				}
			}
			// 如果不是有效 header，移动到下一个字节继续查找
			p++
		}
	}

	// 遍历完所有 payloads 都未找到有效 header
	return -1, -1, 0, 0
}

func processAudio(block cipher.Block, audioMap map[int]*AudioFrame, ts *TSPacket, iv []byte, streamType byte, packageIndex int) {
	if ts.PES == nil || len(ts.PES.ES) == 0 {
		return
	}

	pid := ts.PID
	es := ts.PES.ES

	currenAudioFrame, exists := audioMap[pid]
	if !exists {
		currenAudioFrame = &AudioFrame{
			PID:      pid,
			Payloads: [][]byte{},
		}
		audioMap[pid] = currenAudioFrame
	}

	currenAudioFrame.Payloads = append(currenAudioFrame.Payloads, es)

	for {
		startPayloadIdx, startPos, headerLen, _ := findAudioNextHeaderAcrossTS(streamType, currenAudioFrame.Payloads, 0, 0)
		if startPayloadIdx < 0 {
			break
		}

		nextPayloadIdx, nextPos, _, _ := findAudioNextHeaderAcrossTS(streamType, currenAudioFrame.Payloads, startPayloadIdx, startPos+headerLen)

		if nextPayloadIdx < 0 {
			// 剩余半个 AUDIO TS
			break
		}

		// 拼接完整 AUDIO 数据
		audioData := []byte{}
		for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
			start := 0
			end := len(currenAudioFrame.Payloads[i])
			if i == startPayloadIdx {
				start = startPos
			}
			if i == nextPayloadIdx {
				end = nextPos
			}
			audioData = append(audioData, currenAudioFrame.Payloads[i][start:end]...)
		}

		if len(audioData) > headerLen+16 {
			utils.DecryptCBCSInPlace(block, audioData[headerLen+16:], iv, 1, 0)

			// 回填原始 Payloads
			offset := 0
			for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
				start := 0
				end := len(currenAudioFrame.Payloads[i])
				if i == startPayloadIdx {
					start = startPos
				}
				if i == nextPayloadIdx {
					end = nextPos
				}
				size := end - start
				copy(currenAudioFrame.Payloads[i][start:end], audioData[offset:offset+size])
				offset += size
			}
		}

		oldPayloads := currenAudioFrame.Payloads
		newPayloads := [][]byte{}

		if nextPayloadIdx < len(oldPayloads) {
			newPayloads = append(newPayloads, oldPayloads[nextPayloadIdx][nextPos:])
		}

		// 后续完整 payloads
		for i := nextPayloadIdx + 1; i < len(oldPayloads); i++ {
			newPayloads = append(newPayloads, oldPayloads[i])
		}

		currenAudioFrame.Payloads = newPayloads
	}
}
