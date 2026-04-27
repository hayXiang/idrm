package decrypt

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

func modifyInitM4s(mp4File *mp4.File) *mp4.SinfBox {
	// 移除 pssh box
	var newBoxes []mp4.Box
	for _, box := range mp4File.Moov.Children {
		if box.Type() != "pssh" {
			newBoxes = append(newBoxes, box)
		}
	}
	mp4File.Moov.Children = newBoxes
	var sinfcBox *mp4.SinfBox
	// 遍历 trak，移除 sinf box
	for _, trak := range mp4File.Moov.Traks {
		if trak.Mdia != nil && trak.Mdia.Minf != nil && trak.Mdia.Minf.Stbl != nil && trak.Mdia.Minf.Stbl.Stsd != nil && trak.Mdia.Minf.Stbl.Stsd.Encv != nil {
			original_type := trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf.Frma.DataFormat
			var newBoxes []mp4.Box
			for _, box := range trak.Mdia.Minf.Stbl.Stsd.Encv.Children {
				if box.Type() != "sinf" {
					newBoxes = append(newBoxes, box)
				} else if trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf != nil {
					sinfcBox = trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf
				}
			}
			trak.Mdia.Minf.Stbl.Stsd.Encv.Children = newBoxes
			trak.Mdia.Minf.Stbl.Stsd.Encv.SetType(original_type)
		}

		if trak.Mdia != nil && trak.Mdia.Minf != nil && trak.Mdia.Minf.Stbl != nil && trak.Mdia.Minf.Stbl.Stsd != nil && trak.Mdia.Minf.Stbl.Stsd.Enca != nil {
			original_type := trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf.Frma.DataFormat
			var newBoxes []mp4.Box
			for _, box := range trak.Mdia.Minf.Stbl.Stsd.Enca.Children {
				if box.Type() != "sinf" {
					newBoxes = append(newBoxes, box)
				} else if trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf != nil {
					sinfcBox = trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf
				}
			}
			trak.Mdia.Minf.Stbl.Stsd.Enca.Children = newBoxes
			trak.Mdia.Minf.Stbl.Stsd.Enca.SetType(original_type)
		}
	}
	return sinfcBox
}

func encodeMP4ToBytes(f *mp4.File) ([]byte, error) {
	buf := &bytes.Buffer{}
	err := f.Encode(buf) // Encode 会把 MP4 写入 io.Writer
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func ModifyInitM4sFromBody(data []byte) ([]byte, *mp4.SinfBox, error) {
	mp4File, err := mp4.DecodeFile(bytes.NewReader(data))
	if err != nil {
		println("Error parsing MP4 file:", err.Error())
		return nil, nil, fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	// 添加日志确认MP4文件创建成功并检查结构
	if mp4File != nil {
		println("MP4 file created successfully")
		
		if mp4File.Moov != nil {
			println("Moov box found in MP4 file")
			if mp4File.Moov.Traks != nil {
				println("Number of tracks:", len(mp4File.Moov.Traks))
			}
		} else {
			println("No Moov box found in MP4 file - this may indicate a non-standard init segment")
			
			// 检查segments和fragments
			if len(mp4File.Segments) > 0 {
				println("Segments found in MP4 file:", len(mp4File.Segments))
				for i, seg := range mp4File.Segments {
					println("Segment", i, "has", len(seg.Fragments), "fragments")
					if len(seg.Fragments) > 0 {
						frag := seg.Fragments[0] // 检查第一个fragment
						if frag.Moof != nil {
							println("First fragment contains moof box")
						}
					}
				}
			} else {
				println("No segments found in the file")
			}
			
			// 直接返回原始数据，不进行修改
			return data, nil, nil
		}
	} else {
		println("Failed to create MP4 file")
		return nil, nil, fmt.Errorf("MP4 file creation failed")
	}

	sinfBox := modifyInitM4s(mp4File)
	body, error := encodeMP4ToBytes(mp4File)
	return body, sinfBox, error
}

func modifyInitM4sFromFile(inPath, outPath string) error {
	// 打开输入文件
	inFile, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("打开输入文件失败: %w", err)
	}
	defer inFile.Close()

	// 解析 MP4 文件
	mp4File, err := mp4.DecodeFile(inFile)
	if err != nil {
		return fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	modifyInitM4s(mp4File)

	// 写入输出文件
	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer outFile.Close()

	err = mp4File.Encode(outFile)
	if err != nil {
		return fmt.Errorf("写入 MP4 文件失败: %w", err)
	}
	return nil
}