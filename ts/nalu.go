// NALU 结构体，支持跨多个 PES payload
package ts

import (
	"crypto/cipher"
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
			utils.DecryptCBCSInPlace(block, naluEBSP[unencryptedLeaderBytes:], iv, 1, 9)
		}
		nalu.buffer = naluData[:naluPayloadOffset+len(naluEBSP)]
	}
}

func splitNaluStrict(pesData []byte) []*NALU {
	var nalus []*NALU
	if len(pesData) == 0 {
		return nalus
	}

	preNaluStartPos := -1
	preNaluStartCodeLen := -1
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

			if preNaluStartPos != -1 {
				// 上一个 NALU 结束于当前 start code 前
				nalus = append(nalus, &NALU{
					startCodeLen: preNaluStartCodeLen, // ✅ 修正为上一个 NALU 的 start code
					buffer:       pesData[preNaluStartPos:startCodeStart],
				})
			}

			// 新 NALU 从当前 start code 开始
			preNaluStartPos = startCodeStart
			preNaluStartCodeLen = startCodeLen
			zeroCount = 0
		} else {
			zeroCount = 0
		}

		pos++
	}

	// 最后一个 NALU（尾部）
	if preNaluStartPos != -1 {
		nalus = append(nalus, &NALU{
			startCodeLen: preNaluStartCodeLen,
			buffer:       pesData[preNaluStartPos:],
		})
	}

	return nalus
}
