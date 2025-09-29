package main

import (
	"crypto/cipher"
	"idrm/utils"

	"github.com/Eyevinn/mp4ff/mp4"
)

// 生成 16 字节 CBC IV
func generateIV(mediaSequence int32, index int) [16]byte {
	var iv [16]byte
	seq := uint32(mediaSequence) + uint32(index)
	iv[12] = byte((seq >> 24) & 0xFF)
	iv[13] = byte((seq >> 16) & 0xFF)
	iv[14] = byte((seq >> 8) & 0xFF)
	iv[15] = byte(seq & 0xFF)
	return iv
}

func DecryptFairplaySample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32, sinf *mp4.SinfBox) {
	encrypted := mdat.Data
	var iv16 [16]byte
	iv := getIV(senc, sinf, i, &iv16)

	var cryptByteBlock int = 1
	var skipByteBlock int = 9
	if sinf != nil && sinf.Schi != nil && sinf.Schi.Tenc != nil {
		cryptByteBlock = int(sinf.Schi.Tenc.DefaultCryptByteBlock)
		skipByteBlock = int(sinf.Schi.Tenc.DefaultSkipByteBlock)
	}

	if senc == nil || senc.SubSamples == nil {
		size := traf.Trun.Samples[i].Size
		utils.DecryptCBCSInPlace(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock, true)
	} else {
		for _, sub := range senc.SubSamples[i] {
			offset += uint32(sub.BytesOfClearData)
			size := uint32(sub.BytesOfProtectedData)
			if size > 0 {
				utils.DecryptCBCSInPlace(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock, true)
				offset += size
			}
		}
	}
}
