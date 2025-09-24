package ts

import (
	"bytes"
	"encoding/binary"
)

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

// PMT 解析器，支持跨 TS 包
type PMT struct {
	ts     *TSPacket
	buffer []byte
}

func (p *PMT) Init(ts *TSPacket) map[int]byte {
	if ts == nil || ts.Payload == nil {
		return nil
	}

	p.ts = ts

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
