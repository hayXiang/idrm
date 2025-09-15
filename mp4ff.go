package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/Eyevinn/mp4ff/mp4"
)

func modifyInitM4s(mp4File *mp4.File) *mp4.TencBox {
	// 移除 pssh box
	var newBoxes []mp4.Box
	for _, box := range mp4File.Moov.Children {
		if box.Type() != "pssh" {
			newBoxes = append(newBoxes, box)
		}
	}
	mp4File.Moov.Children = newBoxes
	var tencBox *mp4.TencBox
	// 遍历 trak，移除 sinf box
	for _, trak := range mp4File.Moov.Traks {
		if trak.Mdia != nil && trak.Mdia.Minf != nil && trak.Mdia.Minf.Stbl != nil && trak.Mdia.Minf.Stbl.Stsd != nil && trak.Mdia.Minf.Stbl.Stsd.Encv != nil {
			original_type := trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf.Frma.DataFormat
			var newBoxes []mp4.Box
			for _, box := range trak.Mdia.Minf.Stbl.Stsd.Encv.Children {
				if box.Type() != "sinf" {
					newBoxes = append(newBoxes, box)
				} else if trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf != nil && trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf.Schi != nil {
					tencBox = trak.Mdia.Minf.Stbl.Stsd.Encv.Sinf.Schi.Tenc
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
				} else if trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf != nil && trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf.Schi != nil {
					tencBox = trak.Mdia.Minf.Stbl.Stsd.Enca.Sinf.Schi.Tenc
				}
			}
			trak.Mdia.Minf.Stbl.Stsd.Enca.Children = newBoxes
			trak.Mdia.Minf.Stbl.Stsd.Enca.SetType(original_type)
		}
	}
	return tencBox
}

func encodeMP4ToBytes(f *mp4.File) ([]byte, error) {
	buf := &bytes.Buffer{}
	err := f.Encode(buf) // Encode 会把 MP4 写入 io.Writer
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func modifyInitM4sFromBody(data []byte) ([]byte, *mp4.TencBox, error) {
	mp4File, err := mp4.DecodeFile(bytes.NewReader(data))
	if err != nil {
		return nil, nil, fmt.Errorf("解析 MP4 文件失败: %w", err)
	}

	tencbox := modifyInitM4s(mp4File)
	body, error := encodeMP4ToBytes(mp4File)
	return body, tencbox, error
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

func xmain() {
	if len(os.Args) != 3 {
		fmt.Println("用法: mp4ff <输入文件> <输出文件>")
		return
	}
	inPath := os.Args[1]
	outPath := os.Args[2]
	err := modifyInitM4sFromFile(inPath, outPath)
	if err != nil {
		fmt.Println("处理失败:", err)
	} else {
		fmt.Println("处理完成")
	}
}
