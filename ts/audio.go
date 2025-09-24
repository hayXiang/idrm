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

func findNextADTSHeaderAcrossTS(payloads [][]byte, startIdx, startPos int) (int, int, int, int) {
	for i := startIdx; i < len(payloads); i++ {
		data := payloads[i]
		pos := 0
		if i == startIdx {
			pos = startPos
		}
		for pos+7 <= len(data) {
			if data[pos] == 0xFF && (data[pos+1]&0xF0) == 0xF0 {
				// CRC 判断
				headerLen := 7
				if (data[pos+1] & 0x01) == 0 { // protection_absent = 0
					headerLen = 9
				}

				// header 跨 payload
				if pos+headerLen > len(data) {
					// header 不完整，等待下一 payload
					break
				}

				frameLen := int((uint16(data[pos+3]&0x03) << 11) | (uint16(data[pos+4]) << 3) | (uint16(data[pos+5]&0xE0) >> 5))
				return i, pos, headerLen, frameLen
			}
			pos++
		}
	}
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
