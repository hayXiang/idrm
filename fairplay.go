package main

import (
	"crypto/cipher"

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

func DecryptFairplaySample(block cipher.Block, mdat *mp4.MdatBox, senc *mp4.SencBox, traf *mp4.TrafBox, i int, offset uint32, sinf *mp4.SinfBox) ([]byte, error) {
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
		return decryptCBCSWithTail(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock)
	} else {
		var sampleData []byte
		for _, sub := range senc.SubSamples[i] {
			//sampleData = append(sampleData, encrypted[offset:offset+uint32(sub.BytesOfClearData)]...)
			offset += uint32(sub.BytesOfClearData)
			size := uint32(sub.BytesOfProtectedData)
			if size > 0 {
				decryptCBCSInPlace(block, encrypted[offset:offset+size], iv, cryptByteBlock, skipByteBlock)
				//sampleData = append(sampleData, encrypted[offset:offset+size]...)
				offset += size
			}
		}
		return sampleData, nil
	}
}

func decryptCBCSWithTail(block cipher.Block, subSampleData []byte, iv []byte, cryptByteBlock, skipByteBlock int) ([]byte, error) {
	blockSize := block.BlockSize()
	size := len(subSampleData)
	decrypted := make([]byte, size)

	if cryptByteBlock <= 0 {
		cryptByteBlock = 1
	}
	if skipByteBlock <= 0 {
		skipByteBlock = 0
	}

	copy(decrypted, subSampleData)
	offset := 0
	prevCipher := make([]byte, blockSize)
	copy(prevCipher, iv[:])

	tmp := make([]byte, blockSize)
	cipherBlock := make([]byte, blockSize)

	for offset < size {
		// 解密 cryptByteBlock 个 block
		for i := 0; i < cryptByteBlock && offset < size; i++ {
			remain := size - offset
			if remain >= blockSize {
				copy(cipherBlock, decrypted[offset:offset+blockSize])
				block.Decrypt(tmp, decrypted[offset:offset+blockSize])
				for j := 0; j < blockSize; j++ {
					decrypted[offset+j] = tmp[j] ^ prevCipher[j]
				}
				copy(prevCipher, cipherBlock)
				offset += blockSize
			} else {
				// 尾部不足 block，保留明文
				offset += remain
			}
		}

		// 跳过 skipByteBlock 个 block
		for i := 0; i < skipByteBlock && offset < size; i++ {
			remain := size - offset
			if remain >= blockSize {
				offset += blockSize
			} else {
				// 尾部不足 block，直接保留明文
				offset += remain
			}
		}
	}
	return decrypted, nil
}

func decryptCBCSInPlace(block cipher.Block, data []byte, iv []byte, cryptByteBlock, skipByteBlock int) {
	blockSize := block.BlockSize()
	size := len(data)

	if cryptByteBlock <= 0 {
		cryptByteBlock = 1
	}
	if skipByteBlock <= 0 {
		skipByteBlock = 0
	}

	offset := 0
	prevCipher := make([]byte, blockSize)
	copy(prevCipher, iv) // iv 长度必须等于 blockSize

	tmp := make([]byte, blockSize)
	cipherBlock := make([]byte, blockSize)

	for offset < size {
		// 解密 cryptByteBlock 个 block
		for i := 0; i < cryptByteBlock && offset < size; i++ {
			remain := size - offset
			if remain >= blockSize {
				// 保存当前密文 block
				copy(cipherBlock, data[offset:offset+blockSize])
				// CBC 解密
				block.Decrypt(tmp, data[offset:offset+blockSize])
				for j := 0; j < blockSize; j++ {
					data[offset+j] = tmp[j] ^ prevCipher[j]
				}
				copy(prevCipher, cipherBlock)
				offset += blockSize
			} else {
				// 尾部不足 block，保留明文
				offset += remain
			}
		}

		// 跳过 skipByteBlock 个 block
		for i := 0; i < skipByteBlock && offset < size; i++ {
			remain := size - offset
			if remain >= blockSize {
				offset += blockSize
			} else {
				offset += remain
			}
		}
	}
}
