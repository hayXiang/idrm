package main

import (
    "fmt"
    "os"

    "github.com/Eyevinn/mp4ff/mp4"
)

func removePsshAndSinf(inPath, outPath string) error {
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

    // 移除 pssh box
    var newBoxes []mp4.Box
    for _, box := range mp4File.Moov.Children {
        if box.Type() != "pssh" {
            newBoxes = append(newBoxes, box)
        }
    }
    mp4File.Moov.Children = newBoxes

    // 遍历 trak，移除 sinf box
    for _, trak := range mp4File.Moov.Traks {
        if trak.Mdia != nil && trak.Mdia.Minf != nil && trak.Mdia.Minf.Stbl != nil && trak.Mdia.Minf.Stbl.Stsd != nil && trak.Mdia.Minf.Stbl.Stsd.Encv != nil {
            var newBoxes []mp4.Box
            for _, box := range trak.Mdia.Minf.Stbl.Stsd.Encv.Children  {
                if box.Type() != "sinf" {
                    newBoxes = append(newBoxes, box)
                }
            }
            trak.Mdia.Minf.Stbl.Stsd.Encv.Children = newBoxes
        }
    }

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

func _main() {
    if len(os.Args) != 3 {
        fmt.Println("用法: mp4ff <输入文件> <输出文件>")
        return
    }
    inPath := os.Args[1]
    outPath := os.Args[2]
    err := removePsshAndSinf(inPath, outPath)
    if err != nil {
        fmt.Println("处理失败:", err)
    } else {
        fmt.Println("处理完成")
    }
}