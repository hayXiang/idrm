package ts

import "encoding/binary"

// PAT 解析器，支持跨 TS 包
type PAT struct {
	buffer []byte
}

// 将 TS payload 写入 PAT 缓冲区，返回解析好的 map[PMT PID]ProgramNumber
func (p *PAT) Init(ts *TSPacket) map[int]int {
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
