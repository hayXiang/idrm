# idrm

一个高性能的 DRM 流媒体代理与管理系统，支持 FairPlay/Widevine 解密、HLS/DASH 转换、智能缓存加速，并提供完整的 Web 管理界面。

---

## ✨ 核心特性

### 🔐 DRM 支持
- **FairPlay** - Apple 设备 DRM 解密
- **Widevine** - Google/Android 设备 DRM 解密
- **CBCS/AES-128** - 通用加密方案支持

### 📺 流媒体处理
- **HLS 代理** - M3U8/TS 流实时代理与优化
- **DASH 转 HLS** - 自动将 DASH 流转换为 HLS 格式
- **TS 解析** - 自研 TS 包解析器（PAT/PMT/PES/NALU）
- **码率选择** - 支持仅保留最高码率 (`--best-quality`)

### ⚡ 性能优化
- **多级缓存**：
  - 清单文件缓存（M3U8/MPD）
  - 分片文件缓存（TS/M4S）
  - 内存缓存加速
- **预加载机制** - 分片预加载，秒级启动播放
- **Fasthttp 引擎** - 高并发低延迟 HTTP 服务
- **自动 GC** - 智能内存回收，防止内存泄漏

### 🌐 网络增强
- **代理支持** - SOCKS5/HTTP 代理（可分别配置 M3U 和媒体流代理）
- **自定义请求头** - 支持 User-Agent 和任意 HTTP Header
- **灵活订阅** - 支持单个 M3U URL 或批量 JSON 配置

### 🖥️ Web 管理界面
- **仪表盘** - 系统状态实时监控
- **提供商管理** - 可视化配置和管理流媒体源
- **频道管理** - 频道的增删改查与测试
- **用户管理** - 多用户权限控制
- **初始化向导** - 首次使用引导配置

---

## 🚀 快速开始

### 启动服务

idrm 采用 Web 管理模式，只需指定监听端口即可启动：

```bash
# Linux/Mac
chmod +x build.sh
./build.sh
./idrm-linux-amd64 -l "0.0.0.0:8080"

# Windows
build.bat
idrm.exe -l "0.0.0.0:8080"
```

**参数说明：**
- `-l` 或 `--listen`：监听地址（默认 `127.0.0.1:1234`）

**其他可选参数：**
```
--cache-dir              缓存目录 (默认 ./)
--pprof-enable           启用性能分析服务器
--pprof-addr             性能分析监听地址 (默认 localhost:7070)
```

### 访问管理界面

浏览器打开：`http://localhost:8080`

### 初始化配置

1. **首次访问**会进入初始化向导
2. **设置管理员账号**密码
3. **添加流媒体提供商**（Provider）
   - 配置 M3U/DASH 源地址
   - 设置代理（SOCKS5/HTTP）
   - 自定义 User-Agent 和 HTTP Header
4. **管理频道列表**（Channels）
   - 频道的增删改查
   - 在线测试播放
5. **查看监控仪表盘**
   - 系统状态实时监控
   - 缓存使用情况
   - 活跃连接数

---

## ⚙️ 高级配置

### 缓存配置

```bash
# 自定义缓存目录
./idrm-linux-amd64 -l "0.0.0.0:8080" --cache-dir "/data/idrm-cache/"
```

### 性能分析

```bash
# 启用 pprof 性能分析
./idrm-linux-amd64 -l "0.0.0.0:8080" --pprof-enable --pprof-addr "localhost:7070"

# 访问性能分析页面
# http://localhost:7070/debug/pprof/
```

### 生产环境部署

```bash
# 后台运行
nohup ./idrm-linux-amd64 -l "0.0.0.0:8080" --cache-dir "/var/cache/idrm/" > idrm.log 2>&1 &

# 使用 systemd 管理（推荐）
# 创建 /etc/systemd/system/idrm.service
```

---

## 📦 下载地址

| 平台 | 架构 | 下载链接 |
|------|------|----------|
| Linux | x86_64 (amd64) | [idrm-linux-amd64](https://live.9528.eu.org/release/idrm/idrm-linux-amd64) |
| Linux | ARM64 | [idrm-linux-arm64](https://live.9528.eu.org/release/idrm/idrm-linux-arm64) |
| Android | ARM64 | [idrm-android-arm64](https://live.9528.eu.org/release/idrm/idrm-android-arm64) |
| Windows | x86_64 | [idrm.exe](https://live.9528.eu.org/release/idrm/idrm.exe) |

---

## 🛠️ 开发指南

### 环境要求

- **Go**: 1.24.5+
- **Node.js**: 16+ (前端开发)
- **npm/yarn**: 包管理工具

### 后端开发

```bash
# 安装依赖
go mod tidy

# 运行开发服务器（需找到 main 入口文件）
go run .

# 构建所有平台
chmod +x build.sh
./build.sh
```

### 前端开发

```bash
cd ui

# 安装依赖
npm install

# 开发模式
npm run dev

# 生产构建
npm run build
```

### Git 配置

```bash
# 首次使用前配置
git config --global user.name "你的名字"
git config --global user.email "你的邮箱"
```

### 忽略文件说明

项目已配置 `.gitignore`，以下文件不会被提交：
- 编译产物：`idrm`, `idrm.exe`, `idrm-linux-*`, `idrm-android-*`
- 构建输出：`dist/`
- 前端依赖：`ui/node_modules/`

---

## 🏗️ 技术架构

### 后端技术栈
- **语言**: Go 1.24.5
- **Web 框架**: Fasthttp v1.65.0（高性能 HTTP 服务）
- **多媒体**: 
  - mp4ff v0.49.0（MP4 处理）
  - 自研 TS 流解析模块
- **DRM**: FairPlay/Widevine/CBCS 解密实现
- **缓存**: go-cache v2.1.0（内存缓存）

### 前端技术栈
- **框架**: Vue.js 3
- **构建工具**: Vite
- **状态管理**: Pinia
- **UI 组件**: Element Plus / Ant Design Vue（推测）

### 系统架构
```
┌─────────────┐         ┌──────────────┐         ┌─────────────┐
│  Web 前端    │ ◄────► │  Go Backend   │ ◄────► │  源站/CDN   │
│  (Vue SPA)  │  API   │  (Fasthttp)   │  Proxy  │  (M3U/DASH) │
└─────────────┘         └──────────────┘         └─────────────┘
                               │
                        ┌──────┴──────┐
                        │  DRM 解密   │
                        │  HLS/DASH   │
                        │  缓存层     │
                        └─────────────┘
```

---

## 🤝 贡献与支持

欢迎提交 Issue 和 Pull Request！

- **问题反馈**: 在 [Issues](../../issues) 中描述你遇到的问题
- **功能建议**: 提出新功能想法或改进建议
- **代码贡献**: Fork 项目并提交 PR

---

## 📄 许可证

本项目采用开源许可证，详见 LICENSE 文件。

---

**注意**: 本项目仅供学习研究使用，请遵守当地法律法规，尊重版权方的合法权益。
