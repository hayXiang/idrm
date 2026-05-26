package ts

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
)

type PES struct {
	headerLength int
	tsPayload    []*TSPacket
	continuity   byte
	buffer       []byte

	lastPTS uint64
	lastDTS uint64
}

func (p *PES) header() []byte {
	return p.buffer[0:p.headerLength]
}

func (p *PES) payload() []byte {
	return p.buffer[p.headerLength:]
}

func (p *PES) add(ts *TSPacket) {
	if ts == nil {
		return
	}
	p.tsPayload = append(p.tsPayload, ts)
	if len(ts.PES.header) > 0 {
		p.buffer = append(p.buffer, ts.PES.header...)
		p.headerLength = len(p.buffer)
	}
	p.buffer = append(p.buffer, ts.PES.ES...)
}

func (p *PES) Process(block cipher.Block, ts *TSPacket, iv []byte) *PES {
	// 老的PES 结束
	var newPES *PES = nil
	if len(p.tsPayload) > 0 && (ts == nil || (p.tsPayload[0].Start && ts.Start)) {
		nalus := splitNaluStrict(p.payload())
		// 计算总长度，一次性分配
		totalLen := 0
		for _, nalu := range nalus {
			nalu.Decrypt(block, iv)
			totalLen += len(nalu.buffer)
		}
		newPayload := p.buffer[p.headerLength : p.headerLength+totalLen]
		offset := 0
		for _, nalu := range nalus {
			copy(newPayload[offset:offset+len(nalu.buffer)], nalu.buffer)
			offset += len(nalu.buffer)
		}

		newPES = &PES{continuity: p.continuity}
		newPES.tsPayload = append(newPES.tsPayload, p.tsPayload...)
		newPES.buffer = p.buffer[:p.headerLength+len(newPayload)]
		UpdatePESLength(newPES.header(), len(newPayload))
		newPES.SplitToTS()
		p.tsPayload = p.tsPayload[:0]
		p.buffer = p.buffer[:0]
		p.continuity = newPES.continuity
		p.headerLength = 0
	}
	p.add(ts)
	return newPES
}

func caluAdaptationFieldInfo(ts *TSPacket, data []byte) (int, int, bool) {
	const tsPacketSize = 188
	const tsHeaderSize = 4
	// 1. 初始化自适应字段基础大小
	adaptFieldSize := 0

	// 检查是否存在自适应字段的标志位 (假设从头部解析到了 flags)
	// 0x10 是 PCR 标志，0x08 是 OPCR 标志
	hasPCR := len(ts.AdaptationField) > 0 && (ts.AdaptationField[0] & 0x10) != 0

	if hasPCR {
		adaptFieldSize = 1 // Length 字段 (1 字节)
		adaptFieldSize += 1 // Flags 字段 (1 字节)
		
		if hasPCR {
			adaptFieldSize += 6 // PCR 占用 6 字节
		}
	}

	// 2. 计算剩余可用数据空间以及需要填充的大小
	stuffingSize := 0
	remainDataSize := tsPacketSize - tsHeaderSize - adaptFieldSize

	if remainDataSize > len(data) {
		// 实际数据不够填满，需要填充
		stuffingSize = remainDataSize - len(data)
		
		if stuffingSize > 0 {
			if adaptFieldSize > 0 {
				// 情况 A: 原本就有自适应字段，直接把填充空间加进去
				adaptFieldSize += stuffingSize
			} else {
				// 情况 B: 原本没有自适应字段，需要凭空创建
				// 至少需要 1 字节的 Length 字段来声明自适应字段的长度
				adaptFieldSize += 1 
				stuffingSize -= 1
				
				// 如果减去 Length 后还有富余，说明需要开始填充内容
				if stuffingSize > 0 {
					// 如果你打算用标准的自适应字段填充，通常会再占用 1 字节的 Flags 字段（写 0x00）
					// 这样后面剩下的全部写 0xFF 填充
					adaptFieldSize += 1
					stuffingSize -= 1
				}
				
				// 加上最终剩余的纯填充字节数
				if stuffingSize > 0 {
					adaptFieldSize += stuffingSize
				}
			}
		}
	}
	return adaptFieldSize, stuffingSize, hasPCR
}


func (pes *PES) SplitToTS() {
	const tsPacketSize = 188
	const tsHeaderSize = 4

	pid := pes.tsPayload[0].PID
	var tsPackets []*TSPacket

	tsPackageIndex := 0
	data := pes.buffer
	//这里可以回填原始的tsPackage,因为解密后的数据只会减少
	for len(data) > 0 {
		current_ts := pes.tsPayload[tsPackageIndex]
		offset := tsHeaderSize

		tsBuffer := pes.tsPayload[tsPackageIndex].buffer
		tsBuffer[0] = 0x47 // sync byte

		// 第二字节: payload_unit_start_indicator + PID 高5位
		if len(tsPackets) == 0 {
			tsBuffer[1] = 0x40 | byte(pid>>8) // start indicator = 1
		} else {
			tsBuffer[1] = byte(pid >> 8)
		}
		tsBuffer[2] = byte(pid & 0xFF)

		// 第四字节: adaptation_field_control + continuity
		// 先设为 payload only
		tsBuffer[3] = 0x10
		adaptFieldSize, stuffingSize, hasPCR := caluAdaptationFieldInfo(current_ts, data)
		if adaptFieldSize > 0 {
			adaptField := tsBuffer[offset : offset+adaptFieldSize]
			tsBuffer[3] = (tsBuffer[3] & 0xCF) | (0x30)	// 设置 adaptation_field_control = 3 (adaptation + payload)
			adaptField[0] = byte(adaptFieldSize - 1) //length 字段，后面跟着的 flags 和 PCR 数据
			if adaptFieldSize > 1 {
				adaptField[1] = 0x00 // 默认 flags 全 0
				if hasPCR {
					adaptField[1] = current_ts.AdaptationField[0] // flags 字段
					adaptField[1] &= 0xF0 // 清除原有的 其他位置的标志位，只保留 PCR 和 OPCR 的标志
				}
			}
			if hasPCR {
				copy(adaptField[2:8], current_ts.AdaptationField[1:7]) // 假设 PCR 数据在原 AdaptationField 的 1-6 字节
			}

			if stuffingSize > 0 {
				// 填充数据
				stuffing := adaptField[adaptFieldSize-stuffingSize : adaptFieldSize]
				for i := 0; i < stuffingSize; i++ {
					stuffing[i] = 0xFF
				}
			}
			offset += len(adaptField)
		}

		tsBuffer[3] = (tsBuffer[3] & 0xF0) | (pes.continuity & 0x0F)
		pes.continuity = (pes.continuity + 1) & 0x0F

		// 剩余可放的 payload 大小
		payloadSize := tsPacketSize - tsHeaderSize - adaptFieldSize
		// 拷贝 payload
		copy(tsBuffer[offset:], data[:payloadSize])
		data = data[payloadSize:]

		ts := TSPacket{}
		ts.packageIndex = pes.tsPayload[tsPackageIndex].packageIndex
		ts.Init(tsBuffer)
		tsPackets = append(tsPackets, &ts)
		tsPackageIndex++
	}
	pes.tsPayload = tsPackets
}

func UpdatePESLength(pesHeader []byte, payloadLength int) error {
	if len(pesHeader) < 6 {
		return fmt.Errorf("PES header too short")
	}

	origLength := int(pesHeader[4])<<8 | int(pesHeader[5])
	if origLength == 0 {
		// PES length = 0 表示未知长度，视频流可以直接保持
		return nil
	}

	newLength := payloadLength
	if len(pesHeader) > 6 {
		newLength += len(pesHeader) - 6
	}

	pesHeader[4] = 0
	pesHeader[5] = 0

	/*
		if newLength > 0xFFFF {
			// 对于大视频帧，推荐直接设为0
			pesHeader[4] = 0
			pesHeader[5] = 0
		} else {
			pesHeader[4] = byte(newLength >> 8)
			pesHeader[5] = byte(newLength & 0xFF)
		}
	*/

	return nil
}

// ValidatePES 检查 PES 数据是否正常
func (pes *PES) ValidatePES() error {
	if len(pes.buffer) < 6 {
		return errors.New("PES too short")
	}

	// 检查 start code 前缀 0x000001
	if pes.buffer[0] != 0x00 || pes.buffer[1] != 0x00 || pes.buffer[2] != 0x01 {
		return errors.New("invalid PES start code")
	}

	streamID := pes.buffer[3]
	pesLen := binary.BigEndian.Uint16(pes.buffer[4:6])

	// 打印基本信息
	fmt.Printf("PES stream_id=0x%X, declared length=%d, actual=%d, packageIndex=%d\n", streamID, pesLen, len(pes.buffer)-6, pes.tsPayload[0].packageIndex)

	// 检查 stream_id 合法性
	if !(streamID >= 0xC0 && streamID <= 0xEF) && streamID != 0xBD && streamID != 0xBE && streamID != 0xBF {
		return fmt.Errorf("unusual stream_id: 0x%X", streamID)
	}

	// 检查长度是否匹配
	if pesLen != 0 { // 0 表示不定长（常见于视频流）
		if int(pesLen) != len(pes.buffer)-6 {
			return fmt.Errorf("PES length mismatch: declared=%d, actual=%d", pesLen, len(pes.buffer)-6)
		}
	}

	// 如果是视频/音频，解析 PTS/DTS
	if len(pes.buffer) > 9 {
		flags := pes.buffer[7]
		headerLen := int(pes.buffer[8])

		if len(pes.buffer) < 9+headerLen {
			return fmt.Errorf("PES header too short: need %d bytes, got %d", headerLen, len(pes.buffer)-9)
		}

		if flags&0x80 != 0 { // PTS
			if headerLen < 5 {
				return fmt.Errorf("PTS flag set but header too short")
			}
			pts := decodePTS(pes.buffer[9 : 9+5])
			if pes.lastPTS != 0 {
				fmt.Printf("PTS=%d (Δ=%d)\n", pts, int64(pts)-int64(pes.lastPTS))
			} else {
				fmt.Printf("PTS=%d\n", pts)
			}
			pes.lastPTS = pts
		}

		if flags&0xC0 == 0xC0 { // both PTS+DTS
			if headerLen < 10 {
				return fmt.Errorf("DTS flag set but header too short")
			}
			dts := decodePTS(pes.buffer[14 : 14+5])
			if pes.lastDTS != 0 {
				fmt.Printf("DTS=%d (Δ=%d)\n", dts, int64(dts)-int64(pes.lastDTS))
			} else {
				fmt.Printf("DTS=%d\n", dts)
			}
			pes.lastDTS = dts

		}
	}

	return nil
}

// decodePTS 从 5 字节解析 PTS/DTS
func decodePTS(b []byte) uint64 {
	return (uint64(b[0]&0x0E) << 29) |
		(uint64(b[1]) << 22) |
		(uint64(b[2]&0xFE) << 14) |
		(uint64(b[3]) << 7) |
		(uint64(b[4]) >> 1)
}

// GetDTS 返回 PES 的 DTS，如果不存在返回 ok=false
func (p *PES) GetDTS() (dts uint64, ok bool) {
	hdr := p.header()
	if len(hdr) < 9 {
		return 0, false
	}

	flags := hdr[7]
	headerLen := int(hdr[8])

	if flags&0xC0 == 0xC0 { // PTS+DTS 都存在
		if headerLen < 10 || len(hdr) < 14+5 {
			return 0, false
		}
		dts = decodePTS(hdr[14 : 14+5])
		return dts, true
	}

	// DTS 不存在
	return 0, false
}

func (p *PES) FillDTS(lastIPDTS uint64) {
	hdr := p.header()
	if len(hdr) < 9 {
		return
	}

	flags := hdr[7]
	headerLen := int(hdr[8])

	if flags&0xC0 != 0xC0 { // 没有 DTS
		// 设置 DTS 标志
		hdr[7] = flags | 0x40
		hdr[8] = byte(headerLen + 5)

		// DTS 编码
		dtsBytes := encodeDTSorPTS(lastIPDTS)

		// 插入到 PTS 后
		insertPos := 9 + 5 // PTS 5 bytes
		if len(hdr) > insertPos {
			hdr = append(hdr[:insertPos], append(dtsBytes, hdr[insertPos:]...)...)
		} else {
			hdr = append(hdr, dtsBytes...)
		}

		// 更新 buffer
		newBuf := append(hdr, p.payload()...)
		p.buffer = newBuf
	}
}

// encodePTS 将 uint64 转成 5 字节 PES PTS/DTS 格式
func encodeDTSorPTS(ts uint64) []byte {
	b := make([]byte, 5)
	b[0] = byte((ts>>29)&0x0E) | 0x10 // 4bits + '0010' marker
	b[1] = byte((ts >> 22) & 0xFF)
	b[2] = byte(((ts >> 14) & 0xFE) | 1) // 7bits + marker
	b[3] = byte((ts >> 7) & 0xFF)
	b[4] = byte(((ts << 1) & 0xFE) | 1) // 7bits + marker
	return b
}
