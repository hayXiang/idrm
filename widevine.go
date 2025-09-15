package main

import (
	"crypto/cipher"

	"github.com/Eyevinn/mp4ff/mp4"
)

func DecryptWidevineSample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32, sinf *mp4.SinfBox) ([]byte, error) {
	encrypted := mdat.Data
	var iv16 [16]byte
	iv := getIV(senc, sinf, i, &iv16)
	stream := cipher.NewCTR(block, iv)

	if senc == nil || senc.SubSamples == nil {
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
