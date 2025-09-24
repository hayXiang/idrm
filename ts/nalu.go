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

// EBSPtoRBSP_Strict 将 EBSP 转回 RBSP
// 规则：
// 连续两个0x00后，如果遇到0x03，
// 且03后面的字节存在且 <=0x03，则删除当前0x03
func EBSPtoRBSP(ebsp []byte) []byte {
	rbsp := make([]byte, 0, len(ebsp))
	zeroCount := 0
	i := 0

	for i < len(ebsp) {
		b := ebsp[i]

		// 检查连续两个0x00后是否遇到防止字节 0x03
		if zeroCount == 2 && b == 0x03 {
			// 看下一个字节是否存在且 <=0x03
			if i+1 < len(ebsp) && ebsp[i+1] <= 0x03 {
				// 当前0x03是防止字节，跳过
				zeroCount = 0
				i++
				continue
			}
			// 如果不存在或 >0x03，则保留当前0x03
		}

		// 写入当前字节
		rbsp = append(rbsp, b)

		// 更新 zeroCount
		if b == 0x00 {
			zeroCount++
		} else {
			zeroCount = 0
		}

		i++
	}

	return rbsp
}

func RBSPToEBSP(rbsp []byte) []byte {
	ebsp := []byte{}
	zeros := 0
	for _, b := range rbsp {
		if zeros == 2 && b <= 0x03 {
			ebsp = append(ebsp, 0x03) // 插入防错字节
			zeros = 0
		}
		ebsp = append(ebsp, b)
		if b == 0x00 {
			zeros++
		} else {
			zeros = 0
		}
	}
	return ebsp
}

// processNALU 解析 PES->NALU 并解密 I/P 帧
func (nalu *NALU) Decrypt(block cipher.Block, iv []byte) {
	naluType := nalu.buffer[nalu.startCodeLen] & 0x1F
	naluData := nalu.buffer
	naluPayloadOffset := nalu.startCodeLen + 1
	unencryptedLeaderBytes := 31

	// 只解密 I/P 帧
	if (len(naluData) > naluPayloadOffset+unencryptedLeaderBytes) && (naluType == 5 || naluType == 1) {
		naluRBSP := EBSPtoRBSP(naluData[naluPayloadOffset:])
		utils.DecryptCBCSInPlace(block, naluRBSP[unencryptedLeaderBytes:], iv, 1, 9)
		//ebsp := RBSPToEBSP(naluRBSP)
		changedNaluData := make([]byte, naluPayloadOffset+len(naluRBSP))
		copy(changedNaluData, naluData[:naluPayloadOffset])
		copy(changedNaluData[naluPayloadOffset:], naluRBSP)
		nalu.buffer = changedNaluData
	}
}
