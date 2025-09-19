package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"

	"github.com/Eyevinn/mp4ff/mp4"
)

func DecryptWidevineSample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32, sinf *mp4.SinfBox) ([]byte, error) {
	encrypted := mdat.Data
	var iv16 [16]byte
	iv := getIV(senc, sinf, i, &iv16)
	stream := cipher.NewCTR(block, iv)

	if senc == nil || senc.SubSamples == nil {
		size := traf.Trun.Samples[i].Size
		stream.XORKeyStream(encrypted[offset:offset+size], encrypted[offset:offset+size])
	} else {
		for _, sub := range senc.SubSamples[i] {
			offset += uint32(sub.BytesOfClearData)
			cipherLen := uint32(sub.BytesOfProtectedData)
			if cipherLen > 0 {
				stream.XORKeyStream(encrypted[offset:offset+cipherLen], encrypted[offset:offset+cipherLen])
				offset += cipherLen
			}
		}
	}
	return []byte{}, nil
}

const tsPacketSize = 188

type PESPacket struct {
	StreamID        byte
	PESHeaderLength int
	ES              []byte // 纯 ES 数据，不含 PES header
}

// TS 包结构
type TSPacket struct {
	PID            int
	Start          bool
	CC             byte
	PCR            uint64
	Payload        []byte
	PES            *PESPacket // 可选，解析后的 PES
	PackageType    byte
	Offset         int
	StreamTypeName string
}

// NALU 结构体，支持跨多个 PES payload
type NALU struct {
	PID       int
	Payloads  [][]byte
	StartCode []byte
	Header    byte
	Type      byte
}

// Stream type 常量，分类命名
const (
	// VIDEO
	STREAM_TYPE_VIDEO_H264  = 0x1B
	STREAM_TYPE_VIDEO_H265  = 0x24
	STREAM_TYPE_VIDEO_MPEG1 = 0x01
	STREAM_TYPE_VIDEO_MPEG2 = 0x02

	// AUDIO
	STREAM_TYPE_AUDIO_AAC_ADTS = 0x0F
	STREAM_TYPE_AUDIO_AAC_LATM = 0x11
	STREAM_TYPE_AUDIO_MPEG1    = 0x03
	STREAM_TYPE_AUDIO_MPEG2    = 0x04
	STREAM_TYPE_AUDIO_AC3      = 0x81
	STREAM_TYPE_AUDIO_EAC3     = 0x87

	// OTHER / PRIVATE
	STREAM_TYPE_PRIVATE = 0x06
)

// StreamType 映射表
var streamTypeDescMap = map[byte]string{
	// VIDEO
	STREAM_TYPE_VIDEO_H264:  "H.264 Video",
	STREAM_TYPE_VIDEO_H265:  "H.265 Video",
	STREAM_TYPE_VIDEO_MPEG1: "MPEG-1 Video",
	STREAM_TYPE_VIDEO_MPEG2: "MPEG-2 Video",

	// AUDIO
	STREAM_TYPE_AUDIO_AAC_ADTS: "AAC Audio (ADTS)",
	STREAM_TYPE_AUDIO_AAC_LATM: "AAC Audio (LATM)",
	STREAM_TYPE_AUDIO_MPEG1:    "MPEG-1 Audio",
	STREAM_TYPE_AUDIO_MPEG2:    "MPEG-2 Audio",
	STREAM_TYPE_AUDIO_AC3:      "AC-3 Audio",
	STREAM_TYPE_AUDIO_EAC3:     "E-AC-3 Audio",

	// OTHER / PRIVATE
	STREAM_TYPE_PRIVATE: "PES private / DVB subtitle / descriptor",
}

// PID → StreamType 映射
var pidStreamType = map[int]byte{}
var pidToProgram = map[int]int{} // PMT PID → Program Number
var fakedPidStreamType = map[int]byte{}

// PAT 解析器，支持跨 TS 包
type PATParser struct {
	buffer []byte
}

// 将 TS payload 写入 PAT 缓冲区，返回解析好的 map[PMT PID]ProgramNumber
func (p *PATParser) FeedTS(ts *TSPacket) map[int]int {
	if ts == nil || ts.Payload == nil {
		return nil
	}

	if ts.Start {
		// PUSI = 1，payload 中第一个字节是 pointer_field
		pointer := int(ts.Payload[0])
		if pointer+1 <= len(ts.Payload) {
			// 清空缓冲，开始新 PAT
			p.buffer = append([]byte{}, ts.Payload[1+pointer:]...)
		} else {
			p.buffer = nil
			return nil
		}
	} else {
		// 累加跨 TS 包的 PAT
		p.buffer = append(p.buffer, ts.Payload...)
	}

	if len(p.buffer) < 8 {
		return nil // 数据不足，等待下一个 TS 包
	}

	// section_length 是低 12 位
	sectionLength := int(binary.BigEndian.Uint16(p.buffer[1:3]) & 0x0FFF)
	if sectionLength+3 > len(p.buffer) {
		return nil // 数据未完整，等待下一个 TS 包
	}

	// program info 解析
	programInfoStart := 8
	programInfoEnd := 3 + sectionLength - 4 // 去掉 CRC32
	if programInfoEnd > len(p.buffer) {
		programInfoEnd = len(p.buffer) - 4
	}

	pidToProgram := make(map[int]int)
	for i := programInfoStart; i+4 <= programInfoEnd; i += 4 {
		programNumber := int(binary.BigEndian.Uint16(p.buffer[i : i+2]))
		pmtPID := int(binary.BigEndian.Uint16(p.buffer[i+2:i+4]) & 0x1FFF)
		pidToProgram[pmtPID] = programNumber
	}

	// 解析完成后可以清空缓冲，等待下一个 PAT
	p.buffer = nil
	return pidToProgram
}

// MPEG-2 CRC32 算法 (无 bit 反转、无 final XOR)
func crc32MPEG2(data []byte) uint32 {
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc ^= uint32(b) << 24
		for i := 0; i < 8; i++ {
			if (crc & 0x80000000) != 0 {
				crc = (crc << 1) ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func modifyPMTStreamType(ts *TSPacket, targetPID int, newStreamType byte) {
	if ts == nil || ts.Payload == nil || !ts.Start {
		return
	}

	pointer := int(ts.Payload[0])
	if pointer+1 >= len(ts.Payload) {
		return
	}

	// PMT section
	buf := ts.Payload[1+pointer:]
	if len(buf) < 12 {
		return
	}

	// section_length
	sectionLength := int(binary.BigEndian.Uint16(buf[1:3]) & 0x0FFF)
	sectionEnd := 3 + sectionLength
	if sectionEnd > len(buf) {
		return // 不是完整 section，直接跳过
	}

	crcStart := sectionEnd - 4

	// program_info_length
	programInfoLength := int(binary.BigEndian.Uint16(buf[10:12]) & 0x0FFF)
	offset := 12 + programInfoLength

	// 遍历 ES 描述
	for offset < crcStart {
		esPID := int(binary.BigEndian.Uint16(buf[offset+1:offset+3]) & 0x1FFF)
		esInfoLen := int(binary.BigEndian.Uint16(buf[offset+3:offset+5]) & 0x0FFF)

		if esPID == targetPID {
			// 修改 stream_type
			buf[offset] = newStreamType

			// 重新计算 CRC
			crc := crc32MPEG2(buf[:crcStart])
			buf[crcStart] = byte(crc >> 24)
			buf[crcStart+1] = byte(crc >> 16)
			buf[crcStart+2] = byte(crc >> 8)
			buf[crcStart+3] = byte(crc)

			break
		}

		offset += 5 + esInfoLen
	}
}

// PMT 解析器，支持跨 TS 包
type PMTParser struct {
	buffer []byte
}

// FeedTS 将 TS payload 写入 PMT 缓冲区
func (p *PMTParser) FeedTS(ts *TSPacket) map[int]byte {
	if ts == nil || ts.Payload == nil {
		return nil
	}

	if ts.Start {
		// PUSI = 1，payload 中第一个字节是 pointer_field
		pointer := int(ts.Payload[0])
		if pointer+1 <= len(ts.Payload) {
			p.buffer = append([]byte{}, ts.Payload[1+pointer:]...)
		} else {
			p.buffer = nil
			return nil
		}
	} else {
		p.buffer = append(p.buffer, ts.Payload...)
	}

	if len(p.buffer) < 12 {
		return nil // 数据不足，等待下一个 TS 包
	}

	// section_length 低 12 位
	sectionLength := int(binary.BigEndian.Uint16(p.buffer[1:3]) & 0x0FFF)
	totalLen := 3 + sectionLength
	if len(p.buffer) < totalLen {
		return nil // 数据未完整，等待下一个 TS 包
	}

	// program info
	programInfoLength := int(binary.BigEndian.Uint16(p.buffer[10:12]) & 0x0FFF)
	offset := 12 + programInfoLength
	end := totalLen - 4 // 去掉 CRC

	pidStreamType := make(map[int]byte)
	for offset+5 <= end {
		streamType := p.buffer[offset]
		esPID := int(binary.BigEndian.Uint16(p.buffer[offset+1:offset+3]) & 0x1FFF)
		esInfoLen := int(binary.BigEndian.Uint16(p.buffer[offset+3:offset+5]) & 0x0FFF)
		if offset+5+esInfoLen > end {
			break // 跨 TS 包，等待下一个 TS 包
		}
		pidStreamType[esPID] = streamType
		offset += 5 + esInfoLen
	}

	// 解析完成，清空缓冲
	p.buffer = nil
	return pidStreamType
}

func parsePES(ts *TSPacket) *PESPacket {
	if ts == nil || ts.Payload == nil || len(ts.Payload) == 0 {
		return nil
	}

	pes := &PESPacket{}
	if ts.Start {
		payload := ts.Payload
		if len(payload) < 9 {
			return nil
		}
		pes.StreamID = payload[3]
		pes.PESHeaderLength = int(payload[8])
		if 9+pes.PESHeaderLength <= len(payload) {
			pes.ES = payload[9+pes.PESHeaderLength:]
		} else {
			pes.ES = []byte{}
		}
	} else {
		pes.ES = ts.Payload
	}
	return pes
}

// 解析单个 TS 包
func parseTSPacket(pkt []byte, offset int) *TSPacket {
	if len(pkt) != tsPacketSize || pkt[0] != 0x47 {
		return nil
	}
	ts := &TSPacket{Offset: offset}
	ts.Start = pkt[1]&0x40 != 0
	ts.PID = int(pkt[1]&0x1F)<<8 | int(pkt[2])
	ts.PackageType = (pkt[3] >> 4) & 0x03
	ts.CC = pkt[3] & 0x0F

	adaptationFieldControl := (pkt[3] >> 4) & 0x03
	payloadOffset := 4
	// Adaptation Field
	if adaptField := adaptationFieldControl; adaptField == 2 || adaptField == 3 {
		adaptLen := int(pkt[4])
		if adaptLen > 0 && 5+adaptLen <= len(pkt) {
			// PCR 位于 adaptation_field 前 6 字节
			if pkt[5]&0x10 != 0 && adaptLen >= 6 {
				pcrBase := uint64(pkt[6])<<25 |
					uint64(pkt[7])<<17 |
					uint64(pkt[8])<<9 |
					uint64(pkt[9])<<1 |
					uint64(pkt[10]>>7)
				ts.PCR = pcrBase
			}
		}
		payloadOffset += 1 + adaptLen
	}
	if payloadOffset < tsPacketSize {
		ts.Payload = pkt[payloadOffset:]
	}

	ts.PES = parsePES(ts)
	return ts
}

// 支持跨 TS 包查找 NALU start
// 返回 tsIndex, pos, startCodeLen
func findNextNALUStartAcrossTS(tsList [][]byte, startTS int, startPos int) (int, int, int) {
	for i := startTS; i < len(tsList); i++ {
		es := tsList[i]
		pos := 0
		if i == startTS {
			pos = startPos
		}
		for pos < len(es)-2 {
			if es[pos] == 0x00 && es[pos+1] == 0x00 {
				if es[pos+2] == 0x01 {
					return i, pos, 3
				} else if pos+3 < len(es) && es[pos+2] == 0x00 && es[pos+3] == 0x01 {
					return i, pos, 4
				}
			}
			pos++
		}
	}
	return -1, -1, 0
}

// processNALU 解析 PES->NALU 并解密 I/P 帧
func processNALU(block cipher.Block, naluMap map[int]*NALU, ts *TSPacket, iv []byte, packageIndex int) {
	if ts.PES == nil || len(ts.PES.ES) == 0 {
		return
	}

	pid := ts.PID
	es := ts.PES.ES

	// 获取或初始化当前 NALU
	currentNALU, exists := naluMap[pid]
	if !exists {
		currentNALU = &NALU{
			PID:      pid,
			Payloads: [][]byte{},
		}
		naluMap[pid] = currentNALU
	}

	// 拼接当前 TS payload
	currentNALU.Payloads = append(currentNALU.Payloads, es)

	for {
		startPayloadIdx, startPos, startCodeLen := findNextNALUStartAcrossTS(currentNALU.Payloads, 0, 0)
		if startPayloadIdx < 0 {
			break
		}
		currentNALU.Type = currentNALU.Payloads[startPayloadIdx][startPos+startCodeLen] & 0x1F

		nextPayloadIdx, nextPos, _ := findNextNALUStartAcrossTS(currentNALU.Payloads, startPayloadIdx, startPos+startCodeLen)

		if nextPayloadIdx < 0 {
			// 剩余半个 NALU，保留到下一个 TS
			break
		}

		// 拼接完整 NALU 数据
		naluData := []byte{}
		for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
			start := 0
			end := len(currentNALU.Payloads[i])
			if i == startPayloadIdx {
				start = startPos
			}
			if i == nextPayloadIdx {
				end = nextPos
			}
			naluData = append(naluData, currentNALU.Payloads[i][start:end]...)
		}

		// 只解密 I/P 帧
		if (len(naluData) > startCodeLen+1+31) && (currentNALU.Type == 5 || currentNALU.Type == 1) {
			decryptCBCSInPlace(block, naluData[startCodeLen+1+31:], iv, 1, 9)

			// 回填原始 Payloads
			offset := 0
			for i := startPayloadIdx; i <= nextPayloadIdx; i++ {
				start := 0
				end := len(currentNALU.Payloads[i])
				if i == startPayloadIdx {
					start = startPos
				}
				if i == nextPayloadIdx {
					end = nextPos
				}
				size := end - start
				copy(currentNALU.Payloads[i][start:end], naluData[offset:offset+size])
				offset += size
			}
		}

		oldPayloads := currentNALU.Payloads
		newPayloads := [][]byte{}

		// 当前 payload 剩余半个 NALU
		if nextPayloadIdx < len(oldPayloads) {
			newPayloads = append(newPayloads, oldPayloads[nextPayloadIdx][nextPos:])
		}

		// 后续完整 payloads
		for i := nextPayloadIdx + 1; i < len(oldPayloads); i++ {
			newPayloads = append(newPayloads, oldPayloads[i])
		}

		currentNALU.Payloads = newPayloads
	}
}

// H264 NALU 类型表
var h264Types = map[int]string{
	1: "Non-IDR Slice",
	5: "IDR Slice",
	6: "SEI",
	7: "SPS",
	8: "PPS",
	9: "AUD",
}

// H265 NALU 类型表
var h265Types = map[int]string{
	32: "VPS",
	33: "SPS",
	34: "PPS",
	39: "SEI Prefix",
	40: "SEI Suffix",
}

func detectCodec(es []byte) byte {
	startCode := []byte{0, 0, 0, 1}
	for {
		idx := bytes.Index(es, startCode)
		if idx < 0 || idx+4 >= len(es) {
			break
		}
		nalu := es[idx+4:]
		if len(nalu) == 0 {
			break
		}

		// H.264: 1 字节 header
		naluTypeH264 := int(nalu[0] & 0x1F)
		if _, ok := h264Types[naluTypeH264]; ok {
			return STREAM_TYPE_VIDEO_H264
		}

		// H.265: 2 字节 header
		if len(nalu) >= 2 {
			naluTypeH265 := int((nalu[0] >> 1) & 0x3F)
			if _, ok := h265Types[naluTypeH265]; ok {
				return STREAM_TYPE_VIDEO_H265
			}
		}

		// 移动到下一个
		es = es[idx+4:]
	}

	for i := 0; i+7 < len(es); i++ {
		// 检测 ADTS AAC header (syncword 0xFFF)
		if es[i] == 0xFF && (es[i+1]&0xF0) == 0xF0 {
			return STREAM_TYPE_AUDIO_AAC_ADTS
		}

		// 检测 AC-3 syncword 0x0B77 (big endian)
		if es[i] == 0x0B && es[i+1] == 0x77 {
			return STREAM_TYPE_AUDIO_AC3
		}

		// 检测 E-AC-3 (Dolby Digital Plus) syncword 0x0B77 或 0x77 0x0B
		// 有些流 E-AC-3 可能字节序不同
		if i+1 < len(es) && es[i] == 0x77 && es[i+1] == 0x0B {
			return STREAM_TYPE_AUDIO_EAC3
		}
	}

	return STREAM_TYPE_PRIVATE
}

// 内存 TS 解密，打印 TS 包日志
func decryptTS(tsData []byte, key []byte, iv []byte) {
	var pat_parser = &PATParser{}
	var pmt_parser = &PMTParser{}
	var pmt_packages []*TSPacket

	block, _ := aes.NewCipher(key)
	var currentNALUMap = map[int]*NALU{}
	var currentAudioMap = map[int]*AudioFrame{}
	packageIndex := -1

	for offset := 0; offset+tsPacketSize <= len(tsData); offset += tsPacketSize {
		packageIndex++
		ts := parseTSPacket(tsData[offset:offset+tsPacketSize], offset)
		if ts == nil {
			continue
		}

		// 获取流类型名称
		streamTypeName := "Unknown"
		streamType, ok := pidStreamType[ts.PID]
		if ok {
			if name, exists := streamTypeDescMap[streamType]; exists {
				streamTypeName = name
			} else if _streamType, exists := fakedPidStreamType[ts.PID]; exists {
				streamType = _streamType
				streamTypeName = streamTypeDescMap[streamType]
				for _, pmt_ts := range pmt_packages {
					modifyPMTStreamType(pmt_ts, ts.PID, streamType)
				}
				pmt_packages = pmt_packages[:0]
			} else {
				streamType = detectCodec(ts.Payload)
				fakedPidStreamType[ts.PID] = streamType
				streamTypeName = streamTypeDescMap[streamType]
				for _, pmt_ts := range pmt_packages {
					modifyPMTStreamType(pmt_ts, ts.PID, streamType)
				}
				pmt_packages = pmt_packages[:0]
			}
		} else if ts.PID == 0x0000 {
			streamTypeName = "PAT"
		} else if _, isPMT := pidToProgram[ts.PID]; isPMT {
			streamTypeName = "PMT"
		}
		ts.StreamTypeName = streamTypeName

		//fmt.Printf("%d, %08X, %d, %t, %d, %d, %s\n", packageIndex, ts.Offset, ts.PID, ts.Start, ts.PCR, ts.CC, streamTypeName)

		if ts.Payload == nil {
			continue
		}

		// PAT
		if ts.PID == 0x0000 && ts.Start {
			pidToProgram = pat_parser.FeedTS(ts)
			continue
		}

		// PMT
		if _, ok := pidToProgram[ts.PID]; ok && ts.Start {
			pidStreamType = pmt_parser.FeedTS(ts)
			pmt_packages = append(pmt_packages, ts)
			//fmt.Printf("Parse PMT for program %d, PID=0x%X\n", ——, ts.PID)
			continue
		}

		// 视频流按 NALU 解密
		switch streamType {
		case STREAM_TYPE_VIDEO_H265, STREAM_TYPE_VIDEO_H264:
			processNALU(block, currentNALUMap, ts, iv, packageIndex)
		case STREAM_TYPE_AUDIO_AAC_ADTS, STREAM_TYPE_AUDIO_AC3, STREAM_TYPE_AUDIO_EAC3:
			processAudio(block, currentAudioMap, ts, iv, streamType, packageIndex)
		default:
			continue
		}
	}
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
			decryptCBCSInPlace(block, audioData[headerLen+16:], iv, 1, 0)

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

// func hexToBytes(s string) []byte {
// 	b, _ := hex.DecodeString(s)
// 	return b
// }

// func test() {
// 	data, err := os.ReadFile("D://audio.ts")
// 	if err != nil {
// 		fmt.Println(err)
// 		return
// 	}
// 	key := hexToBytes("ca960e1c8e8294a31ab1d28e6848fcc5") // 示例 AES key
// 	iv := hexToBytes("3E75EE53CB87366AD4EF3A2CBA2E0636")
// 	decryptTS(data, key, iv)

// 	os.WriteFile("D://de.ts", data, 0644)
// 	fmt.Println("Done")
// 	os.Exit(1)
// }
