# idrm

一个高性能的DRM流媒体代理工具，支持 DASH/HLS 转换、缓存加速、自定义请求头/代理，并提供方便的配置方式。

---

## ✨ 功能特性

* 支持 **订阅m3u地址** (`-i`, `--input`) 或 **JSON 配置文件** (`-c`)。
* 支持 **SOCKS5,HTTP 代理** (`--proxy`, `--m3u-proxy`)。
* 可自定义 **User-Agent** 和 **HTTP 请求头**。
* **缓存机制**：

  * 清单缓存（`--cache-manifest`）
  * 分片文件缓存（`--cache-segment-file`）
  * 内存缓存（`--cache-segment-memory`）
* 自动内存回收 (`--auto-gc`)。
* 支持仅保留最高码率 (`--best-quality`)。
* DASH 转换为 HLS (`--to-hls`)。
* 分片预加载，加快播放启动 (`--speed-up`)。

---

## ⚙️ 参数说明

```
-i, --input             m3u订阅 URL
-c, --config            JSON 配置文件
-l, --listen            代理监听地址 (默认 127.0.0.1:1234)
-A, --user-agent        自定义 User-Agent
--m3u-user-agent        M3U 请求的 User-Agent
--header                自定义 HTTP 请求头，可多次指定
--proxy                 MPD/M3U8 请求代理 (SOCKS5)
--m3u-proxy             M3U 请求代理 (SOCKS5)
--cache-dir             缓存目录 (默认 ./)
--cache-manifest        MPD/M3U8 缓存过期时间 (秒)
--cache-segment-file    TS/M4S 文件缓存过期时间 (秒)
--cache-segment-memory  TS/M4S 内存缓存时间 (秒)
--auto-gc               自动垃圾回收间隔 (秒)
--best-quality          仅保留最高码率 (默认 true)
--speed-up              预加载分片
--to-hls                将 DASH 转换成 HLS
```

---

## 📄 配置文件示例

使用 `-c config.json` 可以批量配置多个 provider。

### 单个流

```json
[
  {
    "name": "astro",
    "url": "https://live.9528.eu.org/xxxx",
    "headers": [
      "User-Agent:Mozilla/5.0 (SMART-TV; LINUX; Tizen 8.0) AppleWebKit/537.36 (KHTML, like Gecko) 108.0.5359.1/8.0 TV Safari/537.36"
    ],
    "to-hls": true
  }
]
```

### 多个流

```json
[
  {
    "name": "astro",
    "url": "https://live.9528.eu.org/xxxx",
    "headers": ["User-Agent:Mozilla/5.0 (SMART-TV; LINUX; Tizen 8.0)"],
    "to-hls": true
  },
  {
    "name": "bbc",
    "url": "https://stream.bbc.com/live.m3u8",
    "headers": ["User-Agent:VLC/3.0.20"],
    "to-hls": false
  },
  {
    "name": "espn",
    "url": "https://example.com/espn.mpd",
    "to-hls": true
  }
]
```

启动方式：

```bash
./idrm-linux-amd64 -c config.json
```

---

## 🔧 使用示例

```bash
# 启动代理并监听 1234 端口
./idrm-linux-amd64 -i "https://example.com/playlist.m3u" -l "0.0.0.0:1234"

# 使用 SOCKS5 代理
./idrm-linux-amd64 -i "https://example.com/playlist.m3u" --proxy "socks5://127.0.0.1:1080"

# 使用配置文件
./idrm-linux-amd64 -c config.json
```

---

## 📦 下载

* Linux-x86: https://live.9528.eu.org/release/idrm/idrm-linux-arm64
* Linux-arm: https://live.9528.eu.org/release/idrm/idrm-linux-amd64
* Windows:   https://live.9528.eu.org/release/idrm/idrm.exe

---

## 🤝 贡献

欢迎提交 Issue 和 PR 来帮助改进项目。
如果你在使用中遇到问题，可以在 Issues 区讨论。
