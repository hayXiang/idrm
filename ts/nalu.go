// NALU 结构体，支持跨多个 PES payload
package ts

import (
	"crypto/cipher"
	"fmt"
	"idrm/utils"
)

type NALU struct {
	startCodeLen int
	buffer       []byte
}

// DeEmulationInPlace 去掉 emulation_prevention_three_byte (0x03)
// strict = true  -> 严格模式 (仅当后续字节 <= 0x03 时跳过)
// strict = false -> 宽松模式 (只要遇到 0x000003 就跳过)
func DeEmulationInPlace(ebsp []byte, strict bool) []byte {
	w := 0
	zeroCount := 0
	for r := 0; r < len(ebsp); r++ {
		b := ebsp[r]

		if zeroCount == 2 && b == 0x03 {
			if !strict || (r+1 < len(ebsp) && ebsp[r+1] <= 0x03) {
				// 跳过当前 0x03
				zeroCount = 0
				continue
			}
		}

		// 写入有效字节
		ebsp[w] = b
		w++

		if b == 0x00 {
			zeroCount++
		} else {
			zeroCount = 0
		}
	}
	return ebsp[:w]
}

func (nalu *NALU) Decrypt(block cipher.Block, iv []byte) {
	naluType := nalu.buffer[nalu.startCodeLen] & 0x1F
	naluData := nalu.buffer
	naluPayloadOffset := nalu.startCodeLen + 1
	unencryptedLeaderBytes := 31

	// 只解密 I/P 帧
	if (len(naluData) > naluPayloadOffset) && (naluType == 5 || naluType == 1) {
		naluEBSP := DeEmulationInPlace(naluData[naluPayloadOffset:], false)
		if len(naluEBSP) > unencryptedLeaderBytes {
			utils.DecryptCBCSInPlace(block, naluEBSP[unencryptedLeaderBytes:], iv, 1, 9, false)
		}
		nalu.buffer = naluData[:naluPayloadOffset+len(naluEBSP)]
	}
}

func splitNaluStrict(pesData []byte) []*NALU {
	var nalus []*NALU
	if len(pesData) == 0 {
		return nalus
	}

	curNaluStartPos := -1
	curNaluStartCodeLen := -1
	pos := 0
	zeroCount := 0

	for pos < len(pesData) {
		b := pesData[pos]

		if b == 0x00 {
			zeroCount++
		} else if b == 0x01 && zeroCount >= 2 {
			// 找到 start code
			startCodeLen := 3
			if zeroCount >= 3 {
				startCodeLen = 4
			}

			startCodeStart := pos - zeroCount

			if curNaluStartPos != -1 {
				// 上一个 NALU 结束于当前 start code 前
				nalus = append(nalus, &NALU{
					startCodeLen: curNaluStartCodeLen, // ✅ 修正为上一个 NALU 的 start code
					buffer:       pesData[curNaluStartPos:startCodeStart],
				})
			}

			// 新 NALU 从当前 start code 开始
			curNaluStartPos = startCodeStart
			curNaluStartCodeLen = startCodeLen
			zeroCount = 0
		} else {
			zeroCount = 0
		}

		pos++
	}

	// 最后一个 NALU（尾部）
	if curNaluStartPos != -1 {
		nalus = append(nalus, &NALU{
			startCodeLen: curNaluStartCodeLen,
			buffer:       pesData[curNaluStartPos:],
		})
	}

	return nalus
}

func (n *NALU) header() byte {
	return n.buffer[n.startCodeLen]
}

// NALUType returns the nal_unit_type (5 bits)
func (n *NALU) NALUType() int {
	return int(n.header() & 0x1F)
}

// IsForbiddenBitSet checks if the forbidden bit is 1 (error)
func (n *NALU) IsForbiddenBitSet() bool {
	return (n.header() & 0x80) != 0
}

// RefIDC returns the nal_ref_idc (2 bits)
func (n *NALU) RefIDC() int {
	return int((n.header() >> 5) & 0x03)
}

// IsKeyFrame checks if it's an IDR frame
func (n *NALU) IsKeyFrame() bool {
	return n.NALUType() == 5
}

// IsSPS checks if it's SPS
func (n *NALU) IsSPS() bool {
	return n.NALUType() == 7
}

// IsPPS checks if it's PPS
func (n *NALU) IsPPS() bool {
	return n.NALUType() == 8
}

// IsSEI checks if it's SEI
func (n *NALU) IsSEI() bool {
	return n.NALUType() == 6
}

// IsAUD checks if it's Access Unit Delimiter
func (n *NALU) IsAUD() bool {
	return n.NALUType() == 9
}

// TypeName returns human-readable name
func (n *NALU) TypeName() string {
	switch n.NALUType() {
	case 1:
		return "Non-IDR Slice (P/B Frame)"
	case 5:
		return "IDR Slice (I Frame)"
	case 6:
		return "SEI"
	case 7:
		return "SPS"
	case 8:
		return "PPS"
	case 9:
		return "Access Unit Delimiter"
	default:
		return fmt.Sprintf("Unknown (type=%d)", n.NALUType())
	}
}

// Validate checks for common issues
func (n *NALU) Validate() error {
	if n.IsForbiddenBitSet() {
		return fmt.Errorf("forbidden_bit is set (0x%02X)", n.header())
	}
	payload := n.buffer[n.startCodeLen:]
	if len(payload) == 0 && !n.IsSEI() && !n.IsAUD() && !n.IsFiller() {
		return fmt.Errorf("empty payload")
	}
	return nil
}

// IsFiller checks if it's filler data
func (n *NALU) IsFiller() bool {
	return n.NALUType() == 12
}
