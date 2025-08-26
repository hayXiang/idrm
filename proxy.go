package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
)

type MP4Box struct {
	Size    uint32
	BoxType [4]byte
	Data    []byte
}

type SencBox struct {
	Version           byte
	Flags             [3]byte
	SampleCount       uint32
	SampleEncryptions []SampleEncryption
}

type SampleEncryption struct {
	IV             []byte
	SubsampleCount uint16
	Subsamples     []Subsample
}

type Subsample struct {
	ClearBytes     uint16
	EncryptedBytes uint32
}

type SchmBox struct {
	Version       byte
	Flags         [3]byte
	SchemeType    [4]byte // 'cenc', 'cbcs', 'cens', 'cbc1'
	SchemeVersion uint32
}

type TencBox struct {
	Version                byte
	Flags                  [3]byte
	DefaultCryptByteBlock  byte
	DefaultSkipByteBlock   byte
	DefaultIsProtected     byte
	DefaultPerSampleIVSize byte
	DefaultKID             [16]byte
	DefaultConstantIV      []byte // 仅当 DefaultPerSampleIVSize = 0 时存在
}

type EncryptionInfo struct {
	SchemeType     string
	IVSize         byte
	CryptByteBlock byte
	SkipByteBlock  byte
}

func readBox(reader *bytes.Reader) (*MP4Box, error) {
	box := &MP4Box{}

	// 读取box大小
	err := binary.Read(reader, binary.BigEndian, &box.Size)
	if err != nil {
		return nil, err
	}

	// 读取box类型
	err = binary.Read(reader, binary.BigEndian, &box.BoxType)
	if err != nil {
		return nil, err
	}

	// 处理大小为1的特殊情况（64位大小）
	var size uint64 = uint64(box.Size)
	if box.Size == 1 {
		err = binary.Read(reader, binary.BigEndian, &size)
		if err != nil {
			return nil, err
		}
		if size > uint64(^uint32(0)) {
			return nil, fmt.Errorf("box太大: %d", size)
		}
	}

	// 如果size为0，表示box延伸到文件末尾
	if box.Size == 0 {
		size = uint64(reader.Len() + 8) // +8 是因为已经读取了size和type
	}

	// 计算数据部分的大小（减去已读取的头部）
	headerSize := uint64(8) // 标准头部大小（size + type）
	if box.Size == 1 {
		headerSize += 8 // 额外的64位大小字段
	}

	if size < headerSize {
		return nil, fmt.Errorf("box大小无效: %d", size)
	}

	dataSize := size - headerSize

	// 读取box数据
	box.Data = make([]byte, dataSize)
	_, err = io.ReadFull(reader, box.Data)
	if err != nil {
		return nil, err
	}

	return box, nil
}

func writeBox(writer io.Writer, box *MP4Box) error {
	// 写入box大小
	err := binary.Write(writer, binary.BigEndian, box.Size)
	if err != nil {
		return err
	}

	// 写入box类型
	err = binary.Write(writer, binary.BigEndian, box.BoxType)
	if err != nil {
		return err
	}

	// 写入box数据
	_, err = writer.Write(box.Data)
	if err != nil {
		return err
	}

	return nil
}

func __main() {
	// 创建子命令
	if len(os.Args) < 2 {
		fmt.Println("用法:")
		fmt.Println("  ./test info <init.m4s> -o <output.m4s>   - 获取加密信息并移除加密box")
		fmt.Println("  ./test dec -i <input.m4s> -t <type> -o <output.m4s> -key <key>  - 解密m4s文件")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "info":
		infoCmd := flag.NewFlagSet("info", flag.ExitOnError)
		outputFile := infoCmd.String("o", "", "输出文件路径")
		infoCmd.Parse(os.Args[2:])

		if infoCmd.NArg() < 1 {
			fmt.Println("请指定init.m4s文件路径")
			os.Exit(1)
		}
		initFile := infoCmd.Arg(0)
		handleInfoCommand(initFile, *outputFile)

	case "dec":
		decCmd := flag.NewFlagSet("dec", flag.ExitOnError)
		inputFile := decCmd.String("i", "", "输入的m4s文件路径")
		encType := decCmd.String("t", "cenc", "加密类型(cenc/cbcs)")
		outputFile := decCmd.String("o", "", "输出的解密文件路径")
		key := decCmd.String("key", "", "解密密钥(16字节hex字符串)")
		decCmd.Parse(os.Args[2:])

		if *inputFile == "" || *encType == "" || *outputFile == "" || *key == "" {
			decCmd.Usage()
			os.Exit(1)
		}
		handleDecCommand(*inputFile, *encType, *outputFile, *key)

	default:
		fmt.Printf("未知命令: %s\n", os.Args[1])
		os.Exit(1)
	}
}

func handleInfoCommand(initFile, outputFile string) {
	// 读取init.m4s文件
	data, err := os.ReadFile(initFile)
	if err != nil {
		fmt.Printf("读取文件失败: %v\n", err)
		os.Exit(1)
	}

	// 查找加密信息
	encInfo, err := findEncryptionInfo(data)
	if err != nil {
		fmt.Printf("获取加密信息失败: %v\n", err)
		os.Exit(1)
	}

	// 打印加密信息
	fmt.Printf("\n加密信息:\n")
	fmt.Printf("方案类型: %s\n", encInfo.SchemeType)
	fmt.Printf("IV大小: %d bytes\n", encInfo.IVSize)
	if encInfo.CryptByteBlock > 0 || encInfo.SkipByteBlock > 0 {
		fmt.Printf("加密块: %d\n", encInfo.CryptByteBlock)
		fmt.Printf("跳过块: %d\n", encInfo.SkipByteBlock)
	}

	// 如果指定了输出文件，移除加密相关box并保存
	if outputFile != "" {
		// 移除加密相关box
		cleanData, err := removeEncryptionBoxes(data)
		if err != nil {
			fmt.Printf("移除加密信息失败: %v\n", err)
			os.Exit(1)
		}

		// 保存清理后的文件
		err = os.WriteFile(outputFile, cleanData, 0644)
		if err != nil {
			fmt.Printf("写入输出文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("已保存清理后的文件到: %s\n", outputFile)
	}
}

func handleDecCommand(inputFile, encType, outputFile, key string) {
	// 读取输入文件
	data, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("读取文件失败: %v\n", err)
		os.Exit(1)
	}

	// 解密文件
	decrypted, err := decryptM4S(data, key)
	if err != nil {
		fmt.Printf("解密失败: %v\n", err)
		os.Exit(1)
	}

	// 写入输出文件
	err = os.WriteFile(outputFile, decrypted, 0644)
	if err != nil {
		fmt.Printf("写入文件失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("解密完成!")
}

func parseSencBox(data []byte) (*SencBox, error) {
	reader := bytes.NewReader(data)
	senc := &SencBox{}

	// 读取版本和flags
	err := binary.Read(reader, binary.BigEndian, &senc.Version)
	if err != nil {
		return nil, err
	}
	err = binary.Read(reader, binary.BigEndian, &senc.Flags)
	if err != nil {
		return nil, err
	}

	// 读取sample count
	err = binary.Read(reader, binary.BigEndian, &senc.SampleCount)
	if err != nil {
		return nil, err
	}

	// 读取每个sample的加密信息
	senc.SampleEncryptions = make([]SampleEncryption, senc.SampleCount)
	for i := uint32(0); i < senc.SampleCount; i++ {
		// 读取IV (8字节)
		iv := make([]byte, 8)
		if _, err := io.ReadFull(reader, iv); err != nil {
			return nil, err
		}
		senc.SampleEncryptions[i].IV = iv

		// 如果有subsample信息
		if senc.Flags[2]&0x02 != 0 {
			err = binary.Read(reader, binary.BigEndian, &senc.SampleEncryptions[i].SubsampleCount)
			if err != nil {
				return nil, err
			}

			senc.SampleEncryptions[i].Subsamples = make([]Subsample, senc.SampleEncryptions[i].SubsampleCount)
			for j := uint16(0); j < senc.SampleEncryptions[i].SubsampleCount; j++ {
				err = binary.Read(reader, binary.BigEndian, &senc.SampleEncryptions[i].Subsamples[j].ClearBytes)
				if err != nil {
					return nil, err
				}
				err = binary.Read(reader, binary.BigEndian, &senc.SampleEncryptions[i].Subsamples[j].EncryptedBytes)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	return senc, nil
}

func parseSchmBox(data []byte) (*SchmBox, error) {
	reader := bytes.NewReader(data)
	schm := &SchmBox{}

	err := binary.Read(reader, binary.BigEndian, &schm.Version)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &schm.Flags)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &schm.SchemeType)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &schm.SchemeVersion)
	if err != nil {
		return nil, err
	}

	return schm, nil
}

func parseTencBox(data []byte) (*TencBox, error) {
	reader := bytes.NewReader(data)
	tenc := &TencBox{}

	err := binary.Read(reader, binary.BigEndian, &tenc.Version)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &tenc.Flags)
	if err != nil {
		return nil, err
	}

	// 读取pattern字节
	var reserved byte
	err = binary.Read(reader, binary.BigEndian, &reserved)
	if err != nil {
		return nil, err
	}

	tenc.DefaultCryptByteBlock = (reserved >> 4) & 0x0F
	tenc.DefaultSkipByteBlock = reserved & 0x0F

	err = binary.Read(reader, binary.BigEndian, &tenc.DefaultIsProtected)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &tenc.DefaultPerSampleIVSize)
	if err != nil {
		return nil, err
	}

	err = binary.Read(reader, binary.BigEndian, &tenc.DefaultKID)
	if err != nil {
		return nil, err
	}

	// 如果DefaultPerSampleIVSize为0，读取常量IV
	if tenc.DefaultPerSampleIVSize == 0 {
		var constIVSize byte
		err = binary.Read(reader, binary.BigEndian, &constIVSize)
		if err != nil {
			return nil, err
		}
		tenc.DefaultConstantIV = make([]byte, constIVSize)
		_, err = io.ReadFull(reader, tenc.DefaultConstantIV)
		if err != nil {
			return nil, err
		}
	}

	return tenc, nil
}

func findEncryptionInfo(data []byte) (*EncryptionInfo, error) {
	reader := bytes.NewReader(data)
	var schmBox *SchmBox
	var tencBox *TencBox

	// 查找moov box
	for reader.Len() > 0 {
		box, err := readBox(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if string(box.BoxType[:]) == "moov" {
			// 在moov中查找trak
			moovReader := bytes.NewReader(box.Data)
			for moovReader.Len() > 0 {
				trakBox, err := readBox(moovReader)
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, err
				}

				if string(trakBox.BoxType[:]) == "trak" {
					// 在trak中查找加密信息
					trakReader := bytes.NewReader(trakBox.Data)
					for trakReader.Len() > 0 {
						mdiaBox, err := readBox(trakReader)
						if err != nil {
							if err == io.EOF {
								break
							}
							return nil, err
						}

						if string(mdiaBox.BoxType[:]) == "mdia" {
							// 在mdia中查找minf
							mdiaReader := bytes.NewReader(mdiaBox.Data)
							for mdiaReader.Len() > 0 {
								minfBox, err := readBox(mdiaReader)
								if err != nil {
									if err == io.EOF {
										break
									}
									return nil, err
								}

								if string(minfBox.BoxType[:]) == "minf" {
									// 在minf中查找stbl
									minfReader := bytes.NewReader(minfBox.Data)
									for minfReader.Len() > 0 {
										stblBox, err := readBox(minfReader)
										if err != nil {
											if err == io.EOF {
												break
											}
											return nil, err
										}

										if string(stblBox.BoxType[:]) == "stbl" {
											// 在stbl中查找stsd
											stblReader := bytes.NewReader(stblBox.Data)
											for stblReader.Len() > 0 {
												stsdBox, err := readBox(stblReader)
												if err != nil {
													if err == io.EOF {
														break
													}
													return nil, err
												}

												if string(stsdBox.BoxType[:]) == "stsd" {
													// 跳过version、flags和entry_count
													stsdReader := bytes.NewReader(stsdBox.Data[8:])
													encvBox, err := readBox(stsdReader)
													if err != nil {
														return nil, err
													}

													if string(encvBox.BoxType[:]) == "encv" {
														// 在encv中查找sinf
														encvReader := bytes.NewReader(encvBox.Data)
														for encvReader.Len() > 0 {
															sinfBox, err := readBox(encvReader)
															if err != nil {
																if err == io.EOF {
																	break
																}
																return nil, err
															}

															if string(sinfBox.BoxType[:]) == "sinf" {
																// 解析sinf中的schm和schi/tenc
																sinfReader := bytes.NewReader(sinfBox.Data)
																for sinfReader.Len() > 0 {
																	innerBox, err := readBox(sinfReader)
																	if err != nil {
																		if err == io.EOF {
																			break
																		}
																		return nil, err
																	}

																	switch string(innerBox.BoxType[:]) {
																	case "schm":
																		schmBox, err = parseSchmBox(innerBox.Data)
																		if err != nil {
																			return nil, fmt.Errorf("解析schm box失败: %v", err)
																		}
																	case "schi":
																		// 在schi中查找tenc
																		schiReader := bytes.NewReader(innerBox.Data)
																		for schiReader.Len() > 0 {
																			tencInnerBox, err := readBox(schiReader)
																			if err != nil {
																				if err == io.EOF {
																					break
																				}
																				return nil, err
																			}
																			if string(tencInnerBox.BoxType[:]) == "tenc" {
																				tencBox, err = parseTencBox(tencInnerBox.Data)
																				if err != nil {
																					return nil, fmt.Errorf("解析tenc box失败: %v", err)
																				}
																				break
																			}
																		}
																	}
																}
																break
															}
														}
														break
													}
												}
											}
											break
										}
									}
									break
								}
							}
							break
						}
					}
					break
				}
			}
			break
		}
	}

	if schmBox == nil || tencBox == nil {
		return nil, fmt.Errorf("未找到必要的加密信息")
	}

	return &EncryptionInfo{
		SchemeType:     string(schmBox.SchemeType[:]),
		IVSize:         tencBox.DefaultPerSampleIVSize,
		CryptByteBlock: tencBox.DefaultCryptByteBlock,
		SkipByteBlock:  tencBox.DefaultSkipByteBlock,
	}, nil
}

func removeEncryptionBoxes(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	writer := new(bytes.Buffer)

	for reader.Len() > 0 {
		box, err := readBox(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("读取box失败: %v", err)
		}

		// 跳过 pssh box
		if string(box.BoxType[:]) == "pssh" {
			fmt.Printf("移除 pssh box (大小: %d)\n", box.Size)
			continue
		}

		if string(box.BoxType[:]) == "moov" {
			moovWriter := new(bytes.Buffer)
			moovReader := bytes.NewReader(box.Data)

			for moovReader.Len() > 0 {
				moovBox, err := readBox(moovReader)
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, err
				}

				if string(moovBox.BoxType[:]) == "trak" {
					trakData, err := cleanTrakBox(moovBox.Data)
					if err != nil {
						return nil, err
					}
					moovBox.Data = trakData
					moovBox.Size = uint32(8 + len(trakData))
				}

				err = writeBox(moovWriter, moovBox)
				if err != nil {
					return nil, err
				}
			}

			box.Data = moovWriter.Bytes()
			box.Size = uint32(8 + len(box.Data))
		}

		err = writeBox(writer, box)
		if err != nil {
			return nil, fmt.Errorf("写入box失败: %v", err)
		}
	}

	return writer.Bytes(), nil
}

// 新增辅助函数，用于清理 trak box
func cleanTrakBox(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	writer := new(bytes.Buffer)

	for reader.Len() > 0 {
		box, err := readBox(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if string(box.BoxType[:]) == "mdia" {
			mdiaData, err := cleanStsdBox(box.Data)
			if err != nil {
				return nil, err
			}
			box.Data = mdiaData
			box.Size = uint32(8 + len(mdiaData))
		}

		err = writeBox(writer, box)
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

// 清理 stsd box 中的加密信息
func cleanStsdBox(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	writer := new(bytes.Buffer)

	for reader.Len() > 0 {
		box, err := readBox(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		if string(box.BoxType[:]) == "stbl" {
			stblWriter := new(bytes.Buffer)
			stblReader := bytes.NewReader(box.Data)

			for stblReader.Len() > 0 {
				stblBox, err := readBox(stblReader)
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, err
				}

				if string(stblBox.BoxType[:]) == "stsd" {
					// 处理 stsd box
					stsdData, err := cleanEncvBox(stblBox.Data)
					if err != nil {
						return nil, err
					}
					stblBox.Data = stsdData
					stblBox.Size = uint32(8 + len(stsdData))
				}

				err = writeBox(stblWriter, stblBox)
				if err != nil {
					return nil, err
				}
			}

			box.Data = stblWriter.Bytes()
			box.Size = uint32(8 + len(box.Data))
		}

		err = writeBox(writer, box)
		if err != nil {
			return nil, err
		}
	}

	return writer.Bytes(), nil
}

// 清理 encv box 中的 sinf
func cleanEncvBox(data []byte) ([]byte, error) {
	reader := bytes.NewReader(data)
	writer := new(bytes.Buffer)

	// 写入 stsd 头部（version、flags 和 entry_count）
	header := make([]byte, 8)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	writer.Write(header)

	// 处理 encv
	encvBox, err := readBox(reader)
	if err != nil {
		return nil, err
	}

	if string(encvBox.BoxType[:]) == "encv" {
		// 从 encv 中移除 sinf
		encvReader := bytes.NewReader(encvBox.Data)
		encvWriter := new(bytes.Buffer)

		for encvReader.Len() > 0 {
			innerBox, err := readBox(encvReader)
			if err != nil {
				if err == io.EOF {
					break
				}
				return nil, err
			}

			// 跳过 sinf box
			if string(innerBox.BoxType[:]) != "sinf" {
				err = writeBox(encvWriter, innerBox)
				if err != nil {
					return nil, err
				}
			} else {
				fmt.Printf("移除 sinf box (大小: %d)\n", innerBox.Size)
			}
		}

		encvBox.Data = encvWriter.Bytes()
		encvBox.Size = uint32(8 + len(encvBox.Data))
	}

	err = writeBox(writer, encvBox)
	if err != nil {
		return nil, err
	}

	return writer.Bytes(), nil
}

func decryptM4S(data []byte, key string) ([]byte, error) {
	reader := bytes.NewReader(data)
	writer := new(bytes.Buffer)
	var sencInfo *SencBox
	var mdatData []byte

	// 第一遍扫描，查找senc和mdat
	for reader.Len() > 0 {
		box, err := readBox(reader)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("读取box失败: %v", err)
		}

		if string(box.BoxType[:]) == "moof" {
			// 在moof中查找traf/senc
			moofReader := bytes.NewReader(box.Data)
			for moofReader.Len() > 0 {
				trafBox, err := readBox(moofReader)
				if err != nil {
					if err == io.EOF {
						break
					}
					return nil, err
				}

				if string(trafBox.BoxType[:]) == "traf" {
					// 在traf中查找senc
					trafReader := bytes.NewReader(trafBox.Data)
					for trafReader.Len() > 0 {
						sencBox, err := readBox(trafReader)
						if err != nil {
							if err == io.EOF {
								break
							}
							return nil, err
						}

						if string(sencBox.BoxType[:]) == "senc" {
							sencInfo, err = parseSencBox(sencBox.Data)
							if err != nil {
								return nil, fmt.Errorf("解析senc box失败: %v", err)
							}
							break
						}
					}
				}
			}
		} else if string(box.BoxType[:]) == "mdat" {
			mdatData = box.Data
		}

		// 写入box（除了mdat，mdat等待解密后写入）
		if string(box.BoxType[:]) != "mdat" {
			err = writeBox(writer, box)
			if err != nil {
				return nil, fmt.Errorf("写入box失败: %v", err)
			}
		}
	}

	if sencInfo == nil {
		return nil, fmt.Errorf("未找到senc box")
	}

	if mdatData == nil {
		return nil, fmt.Errorf("未找到mdat box")
	}

	// 解密mdat数据
	decryptedMdat, err := decryptMdatWithSenc(mdatData, key, sencInfo)
	if err != nil {
		return nil, fmt.Errorf("解密mdat失败: %v", err)
	}

	// 写入解密后的mdat box
	mdatBox := &MP4Box{
		Size:    uint32(8 + len(decryptedMdat)),
		BoxType: [4]byte{'m', 'd', 'a', 't'},
		Data:    decryptedMdat,
	}
	err = writeBox(writer, mdatBox)
	if err != nil {
		return nil, fmt.Errorf("写入解密后的mdat失败: %v", err)
	}

	return writer.Bytes(), nil
}

func decryptMdatWithSenc(data []byte, keyHex string, senc *SencBox) ([]byte, error) {
	// 解析hex格式的密钥
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("解析密钥失败: %v", err)
	}

	// 创建AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建AES cipher失败: %v", err)
	}

	// 创建输出buffer
	decrypted := make([]byte, len(data))
	copy(decrypted, data)

	// 遍历每个sample进行解密
	offset := 0
	for i, sample := range senc.SampleEncryptions {
		// 创建完整的16字节IV (前8字节为0，后8字节来自senc)
		iv := make([]byte, 16)
		copy(iv[8:], sample.IV)

		// 创建CTR模式解密器
		stream := cipher.NewCTR(block, iv)

		if len(sample.Subsamples) > 0 {
			// 处理subsample情况
			sampleOffset := offset
			for _, subsample := range sample.Subsamples {
				// 跳过明文部分
				sampleOffset += int(subsample.ClearBytes)

				// 解密加密部分
				if sampleOffset+int(subsample.EncryptedBytes) > len(data) {
					return nil, fmt.Errorf("样本 #%d 超出范围", i)
				}
				stream.XORKeyStream(
					decrypted[sampleOffset:sampleOffset+int(subsample.EncryptedBytes)],
					data[sampleOffset:sampleOffset+int(subsample.EncryptedBytes)],
				)
				sampleOffset += int(subsample.EncryptedBytes)
			}
			offset = sampleOffset
		} else {
			// 处理整个sample
			sampleSize := 0
			if i < len(senc.SampleEncryptions)-1 {
				nextOffset := offset
				for _, nextSample := range senc.SampleEncryptions[i+1].Subsamples {
					nextOffset += int(nextSample.ClearBytes) + int(nextSample.EncryptedBytes)
				}
				sampleSize = nextOffset - offset
			} else {
				sampleSize = len(data) - offset
			}

			if offset+sampleSize > len(data) {
				return nil, fmt.Errorf("样本 #%d 超出范围", i)
			}

			stream.XORKeyStream(decrypted[offset:offset+sampleSize], data[offset:offset+sampleSize])
			offset += sampleSize
		}
	}

	return decrypted, nil
}
