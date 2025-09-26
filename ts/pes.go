package ts

import (
	"bytes"
	"crypto/cipher"
	"fmt"
)

type PES struct {
	header     []byte
	tsPayload  []*TSPacket
	payload    []byte
	continuity byte
}

func (p *PES) add(ts *TSPacket) {
	if ts == nil {
		return
	}
	p.tsPayload = append(p.tsPayload, ts)
	if len(ts.PES.header) > 0 {
		p.header = append(p.header, ts.PES.header...)
	}
	p.payload = append(p.payload, ts.PES.ES...)
}

func (p *PES) Process(block cipher.Block, ts *TSPacket, iv []byte) *PES {
	// 老的PES 结束
	var newPES *PES = nil
	if len(p.tsPayload) > 0 && (ts == nil || (p.tsPayload[0].Start && ts.Start)) {
		nalus := splitNalu(p.payload)
		// 计算总长度，一次性分配
		totalLen := 0
		for _, nalu := range nalus {
			nalu.Decrypt(block, iv)
			totalLen += len(nalu.buffer)
		}
		newPayload := make([]byte, 0, totalLen)
		for _, nalu := range nalus {
			newPayload = append(newPayload, nalu.buffer...)
		}

		newPES = &PES{continuity: p.continuity}
		//必须用append，会修改长度
		newPES.header = make([]byte, len(p.tsPayload[0].PES.header))
		copy(newPES.header, p.tsPayload[0].PES.header)
		newPES.payload = newPayload
		UpdatePESLength(newPES.header, len(newPayload))

		//PES 分包
		newPES.SplitToTS(p.tsPayload[0].PID, p.tsPayload)
		p.tsPayload = p.tsPayload[:0]
		p.payload = p.payload[:0]
		p.continuity = newPES.continuity
	}
	p.add(ts)
	return newPES
}

func (pes *PES) SplitToTS(pid int, rawTsList []*TSPacket) {
	const tsPacketSize = 188
	const tsHeaderSize = 4

	// 拼接 PES 数据
	data := make([]byte, len(pes.header)+len(pes.payload))
	copy(data, pes.header)
	copy(data[len(pes.header):], pes.payload)

	var tsPackets []*TSPacket

	tsPackageIndex := 0
	for len(data) > 0 {
		tsBuffer := make([]byte, tsPacketSize)
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

		offset := tsHeaderSize
		var adaptField []byte
		//只在PES开头copy adapField
		if tsPackageIndex < len(rawTsList) && tsPackageIndex == 0 {
			rawTs := rawTsList[tsPackageIndex]
			aFlen := len(rawTs.AdaptationField) - rawTs.suffingLength
			adaptField = rawTs.AdaptationField[:aFlen:aFlen]
		}

		stuffingSize := tsPacketSize - tsHeaderSize - len(adaptField) - len(data)
		if stuffingSize < 0 {
			stuffingSize = 0
		}
		if len(adaptField) > 0 {
			tsBuffer[3] = (tsBuffer[3] & 0xCF) | (0x30)
			if stuffingSize > 0 {
				tsBuffer[offset] = byte(len(adaptField) + stuffingSize - 1)
			} else {
				tsBuffer[offset] = byte(len(adaptField))
			}
			offset++
			stuffingSize--
			// 写入 adaptation_field 内容
			copy(tsBuffer[offset:], adaptField)
			offset += len(adaptField)

			for i := 0; i < stuffingSize; i++ {
				if i == 0 {
					tsBuffer[offset] = 0x00
				} else {
					tsBuffer[offset] = 0xFF
				}
				offset++
			}
		} else if stuffingSize > 0 {
			tsBuffer[3] = (tsBuffer[3] & 0xCF) | (0x30)
			tsBuffer[offset] = byte(stuffingSize - 1)

			stuffingSize--
			offset++

			for i := 0; i < stuffingSize; i++ {
				if i == 0 {
					tsBuffer[offset] = 0x00
				} else {
					tsBuffer[offset] = 0xFF
				}
				offset++
			}
		}

		tsBuffer[3] = (tsBuffer[3] & 0xF0) | (pes.continuity & 0x0F)
		pes.continuity = (pes.continuity + 1) & 0x0F

		// 剩余可放的 payload 大小
		payloadSize := tsPacketSize - offset
		// 拷贝 payload
		copy(tsBuffer[offset:], data[:payloadSize])
		data = data[payloadSize:]

		ts := TSPacket{}
		ts.Init(tsBuffer)
		tsPackets = append(tsPackets, &ts)
		tsPackageIndex++
	}

	pes.tsPayload = tsPackets
}

// findNextNALUStart 查找 NALU 起始码 (优先匹配 4 字节)
// 返回起始位置和起始码长度 (3 或 4)，找不到则返回 -1, 0
func findNextNALUStart(data []byte, start int) (int, int) {
	if start >= len(data) {
		return -1, 0
	}

	// 优先查找 4 字节 00 00 00 01
	if idx := bytes.Index(data[start:], []byte{0x00, 0x00, 0x00, 0x01}); idx != -1 {
		return start + idx, 4
	}

	// 再查找 3 字节 00 00 01
	if idx := bytes.Index(data[start:], []byte{0x00, 0x00, 0x01}); idx != -1 {
		return start + idx, 3
	}

	return -1, 0
}

func splitNalu(pesData []byte) []*NALU {
	var nalus []*NALU
	pos := 0
	for {
		startPos, startCodeLen := findNextNALUStart(pesData, pos)
		if startPos == -1 {
			break
		}

		// 找下一个 start code
		nextStart, _ := findNextNALUStart(pesData, startPos+startCodeLen)

		if nextStart == -1 {
			nalus = append(nalus, &NALU{
				startCodeLen: startCodeLen,
				buffer:       pesData[startPos:],
			})
			break
		} else {
			nalus = append(nalus, &NALU{
				startCodeLen: startCodeLen,
				buffer:       pesData[startPos:nextStart],
			})
		}
		pos = nextStart
	}
	return nalus
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

	if newLength > 0xFFFF {
		// 对于大视频帧，推荐直接设为0
		pesHeader[4] = 0
		pesHeader[5] = 0
	} else {
		pesHeader[4] = byte(newLength >> 8)
		pesHeader[5] = byte(newLength & 0xFF)
	}

	return nil
}
