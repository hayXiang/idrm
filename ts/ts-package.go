package ts

import (
	"fmt"
)

const TS_PACKATE_SIZE = 188

type PESPacket struct {
	StreamID byte
	header   []byte
	ES       []byte // 纯 ES 数据，不含 PES header
}

// TS 包结构
type TSPacket struct {
	packageIndex    int
	PID             int
	Start           bool
	CC              byte
	PCR             uint64
	PES             *PESPacket // 可选，解析后的 PES
	PackageType     byte
	StreamTypeName  string
	header          []byte
	AdaptationField []byte
	suffingLength   int
	Payload         []byte
	buffer          []byte //原始数据
}

func (ts *TSPacket) Init(pkt []byte) error {
	ts.buffer = pkt

	//解析
	if len(pkt) != TS_PACKATE_SIZE || pkt[0] != 0x47 {
		return fmt.Errorf("数据错误，长度=%d, 开头=%x", len(pkt), pkt[0])
	}

	ts.Start = pkt[1]&0x40 != 0
	ts.PID = int(pkt[1]&0x1F)<<8 | int(pkt[2])
	ts.PackageType = (pkt[3] >> 4) & 0x03
	ts.CC = pkt[3] & 0x0F
	ts.header = pkt[:4]
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
		payloadOffset += 1
		ts.AdaptationField = pkt[payloadOffset : payloadOffset+adaptLen]
		ts.suffingLength = stuffingSize(ts.AdaptationField)
		payloadOffset += adaptLen
	}
	if payloadOffset < tsPacketSize {
		ts.Payload = pkt[payloadOffset:]
	}

	ts.PES = ts.parsePES()
	return nil
}

// 返回 stuffing 字节数
func stuffingSize(af []byte) int {
	if len(af) == 0 {
		return 0
	}

	flags := af[0]
	offset := 1
	effective := 1 // flags

	if flags&0x10 != 0 { // PCR
		effective += 6
		offset += 6
	}
	if flags&0x08 != 0 { // OPCR
		effective += 6
		offset += 6
	}
	if flags&0x04 != 0 { // splicing point
		effective += 1
		offset += 1
	}
	if flags&0x02 != 0 { // private data
		if offset >= len(af) {
			return 0
		}
		l := int(af[offset])
		effective += 1 + l
		offset += 1 + l
	}
	if flags&0x01 != 0 { // extension
		if offset >= len(af) {
			return 0
		}
		l := int(af[offset])
		effective += 1 + l
		offset += 1 + l
	}

	if effective > len(af) {
		return 0
	}
	return len(af) - effective
}

func (ts *TSPacket) parsePES() *PESPacket {
	if ts.Payload == nil {
		return nil
	}

	pes := &PESPacket{}
	if ts.Start {
		payload := ts.Payload

		pes.StreamID = payload[3]
		optionalHeaderLenth := int(payload[8]) // 扩展域长度

		// PES header 总长度 = 固定 9 + 扩展域长度
		headerLen := 9 + optionalHeaderLenth
		if headerLen <= len(payload) {
			pes.header = payload[:headerLen]
			pes.ES = payload[headerLen:]
		} else {
			// 数据不足，可能是跨 TS 包，需要拼接
			pes.header = payload
			pes.ES = []byte{}
		}
	} else {
		// 非起始包，只有 ES 部分
		pes.ES = ts.Payload
	}
	return pes
}
