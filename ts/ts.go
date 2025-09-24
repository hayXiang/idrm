package ts

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"os"
)

const tsPacketSize = 188

// PID → StreamType 映射
var pidStreamType = map[int]byte{}
var pidToProgram = map[int]int{} // PMT PID → Program Number
var fakedPidStreamType = map[int]byte{}

// 内存 TS 解密，打印 TS 包日志
func DecryptTS(data []byte, key []byte, iv []byte) []byte {
	var pat_parser = &PAT{}
	var pmt_parser = &PMT{}
	var pmt_packages []*TSPacket

	block, _ := aes.NewCipher(key)
	var currentPESMap = map[int]*PES{}
	var currentAudioMap = map[int]*AudioFrame{}
	packageIndex := -1

	var allTS []*TSPacket
	for offset := 0; offset+tsPacketSize <= len(data); offset += tsPacketSize {
		tsData := data[offset : offset+tsPacketSize]
		packageIndex++
		var ts TSPacket
		ts.packageIndex = packageIndex
		err := ts.Init(tsData)
		if err != nil {
			continue
		}

		// 获取流类型名称
		streamTypeName := "Unknown"
		streamType, ok := pidStreamType[ts.PID]
		if ok {
			if name, exists := streamTypeDescMap[streamType]; exists {
				streamTypeName = name
			} else if _streamType, exists := fakedPidStreamType[ts.PID]; exists {
				streamType = _streamType
				streamTypeName = streamTypeDescMap[streamType]
				for _, pmt_ts := range pmt_packages {
					modifyPMTStreamType(pmt_ts, ts.PID, streamType)
				}
				pmt_packages = pmt_packages[:0]
			} else {
				streamType = detectCodec(ts.Payload)
				fakedPidStreamType[ts.PID] = streamType
				streamTypeName = streamTypeDescMap[streamType]
				for _, pmt_ts := range pmt_packages {
					modifyPMTStreamType(pmt_ts, ts.PID, streamType)
				}
				pmt_packages = pmt_packages[:0]
			}

		} else if ts.PID == 0x11 {
			streamTypeName = "SDT/BAT"
		} else if ts.PID == 0x0000 {
			streamTypeName = "PAT"
		} else if _, isPMT := pidToProgram[ts.PID]; isPMT {
			streamTypeName = "PMT"
		}
		ts.StreamTypeName = streamTypeName

		//fmt.Printf("%d, %08X, %d, %t, %d, %d, %s\n", packageIndex, offset, ts.PID, ts.Start, ts.PCR, ts.CC, streamTypeName)

		if ts.Payload == nil {
			allTS = append(allTS, &ts)
			continue
		}

		// PAT
		if ts.PID == 0x0000 && ts.Start {
			pidToProgram = pat_parser.Init(&ts)
			allTS = append(allTS, &ts)
			continue
		}

		// PMT
		if _, ok := pidToProgram[ts.PID]; ok && ts.Start {
			pidStreamType = pmt_parser.Init(&ts)
			pmt_packages = append(pmt_packages, &ts)
			allTS = append(allTS, &ts)
			continue
		}

		// 视频流按 NALU 解密
		switch streamType {
		case STREAM_TYPE_VIDEO_H265, STREAM_TYPE_VIDEO_H264:
			pes, exists := currentPESMap[ts.PID]
			if !exists {
				pes = &PES{continuity: 0}
				currentPESMap[ts.PID] = pes
			}
			if newPES := pes.Process(block, &ts, iv); newPES != nil {
				allTS = append(allTS, newPES.tsPayload...)
			}
			continue
		case STREAM_TYPE_AUDIO_AAC_ADTS, STREAM_TYPE_AUDIO_AC3, STREAM_TYPE_AUDIO_EAC3:
			processAudio(block, currentAudioMap, &ts, iv, streamType, packageIndex)
			allTS = append(allTS, &ts)
			continue
		default:
			allTS = append(allTS, &ts)
			continue
		}
	}
	//fmt.Print(count)
	var ret []byte
	for _, _ts := range allTS {
		ret = append(ret, _ts.buffer...)
	}
	return ret
}

func hexToBytes(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func Test() {
	data, err := os.ReadFile("D://drm/ggg/raw/all.ts")
	//data, err := os.ReadFile("D://drm/012_mute_60s.ts")
	if err != nil {
		fmt.Println(err)
		return
	}
	key := hexToBytes("8bcdab76c02b341fb3658d912b0def9c") // 示例 AES key
	iv := hexToBytes("A2CC00BBA65B2DB60728B7168F5F4B9A")
	body := DecryptTS(data, key, iv)

	os.WriteFile("D://drm/de-new.ts", body, 0644)
	fmt.Println("Done")
	os.Exit(1)
}
