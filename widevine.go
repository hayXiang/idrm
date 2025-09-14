package main

import (
	"crypto/cipher"

	"github.com/Eyevinn/mp4ff/mp4"
)

// 前补零 IV 到 16 字节，使用复用数组避免重复分配
func padIV(iv8 []byte, iv16 *[16]byte) []byte {
	for i := range iv16 {
		iv16[i] = 0
	}
	copy(iv16[:], iv8)
	return iv16[:]
}

func DecryptWidevineSampleTest(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32) ([]byte, error) {
	if i >= len(senc.IVs) {
		return []byte{}, nil
	}
	encrypted := mdat.Data
	// 创建 CTR stream
	var iv16 [16]byte
	iv := padIV(senc.IVs[i], &iv16)
	stream := cipher.NewCTR(block, iv)

	var sampleData []byte
	if senc.SubSamples == nil {
		size := traf.Trun.Samples[i].Size
		stream.XORKeyStream(encrypted[offset:offset+size], encrypted[offset:offset+size])
		sampleData = append(sampleData, encrypted[offset:offset+size]...)
	} else {
		for _, sub := range senc.SubSamples[i] {
			sampleData = append(sampleData, encrypted[offset:offset+uint32(sub.BytesOfClearData)]...)
			offset += uint32(sub.BytesOfClearData)
			cipherLen := uint32(sub.BytesOfProtectedData)
			if cipherLen > 0 {
				stream.XORKeyStream(encrypted[offset:offset+cipherLen], encrypted[offset:offset+cipherLen])
				sampleData = append(sampleData, encrypted[offset:offset+cipherLen]...)
				offset += cipherLen
			}
		}
	}
	return sampleData, nil
}

func DecryptWidevineSample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32) ([]byte, error) {
	if i >= len(senc.IVs) {
		return []byte{}, nil
	}
	encrypted := mdat.Data
	// 创建 CTR stream
	var iv16 [16]byte
	iv := padIV(senc.IVs[i], &iv16)
	stream := cipher.NewCTR(block, iv)

	if senc.SubSamples == nil {
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
