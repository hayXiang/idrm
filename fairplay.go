package main

import (
	"crypto/cipher"

	"github.com/Eyevinn/mp4ff/mp4"
)

// 生成 16 字节 CBC IV
func generateIV(mediaSequence int32, index int) [16]byte {
	if mediaSequence == -1 {
		return [16]byte{0}
	}
	var iv [16]byte
	seq := uint32(mediaSequence) + uint32(index)
	iv[12] = byte((seq >> 24) & 0xFF)
	iv[13] = byte((seq >> 16) & 0xFF)
	iv[14] = byte((seq >> 8) & 0xFF)
	iv[15] = byte(seq & 0xFF)
	return iv
}

func DecryptFairplaySample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32, mediaSequence int32, cryptByteBlock int, skipByteBlock int) {
	encrypted := mdat.Data
	iv := generateIV(mediaSequence, i)
	if senc.SubSamples == nil {
		size := traf.Trun.Samples[i].Size
		DecryptCBCSInPlace(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock)
	} else {
		for _, sub := range senc.SubSamples[i] {
			offset += uint32(sub.BytesOfClearData)
			size := uint32(sub.BytesOfProtectedData)
			if size > 0 {
				DecryptCBCSInPlace(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock)
				offset += size
			}
		}
	}
}

func DecryptCBCSInPlace(block cipher.Block, data []byte, iv [16]byte, cryptBlocks, skipBlocks int) {
	blockSize := block.BlockSize()
	var prevCipher [16]byte
	copy(prevCipher[:], iv[:])
	var tmp [16]byte
	var cipherBlock [16]byte

	offset := 0
	for offset+blockSize <= len(data) {
		// 解密 cryptBlocks 个 block
		for i := 0; i < cryptBlocks && offset+blockSize <= len(data); i++ {
			// 保存密文到临时数组
			copy(cipherBlock[:], data[offset:offset+blockSize])

			// AES 解密
			block.Decrypt(tmp[:], cipherBlock[:])
			for j := 0; j < blockSize; j++ {
				data[offset+j] ^= prevCipher[j]
			}

			// 更新 prevCipher 为密文
			copy(prevCipher[:], cipherBlock[:])
			offset += blockSize
		}

		// 跳过 skipBlocks 个 block
		for i := 0; i < skipBlocks && offset+blockSize <= len(data); i++ {
			offset += blockSize
		}
	}
}
