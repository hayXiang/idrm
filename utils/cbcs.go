package utils

import "crypto/cipher"

func DecryptCBCSInPlace(block cipher.Block, data []byte, iv []byte, cryptByteBlock, skipByteBlock int) {
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
