# LAN Scout

> 局域网服务发现 + 导航页。后台用 `nmap` 周期性扫描本地网段，把发现的主机、开放端口和服务列在一个网页上 —— Web 服务一键点击跳转，结果持久化，还能自定义分类、排序、隐藏/显示。

零第三方依赖：Python 标准库 + SQLite，前端单文件，唯一外部程序是 `nmap`。

![license](https://img.shields.io/badge/license-MIT-blue) ![python](https://img.shields.io/badge/python-3.10%2B-blue) ![deps](https://img.shields.io/badge/python%20deps-0-brightgreen)

## 功能

- 🔍 **自动 + 手动扫描**：后台按间隔自动扫，页面也能随时「立即扫描」。
- 🧭 **两种视图**：按主机看设备，或按分类看「服务导航」。
- 🏷️ **自定义分类**：把服务按端口/服务名归类，自定义名称、颜色、顺序，整类可隐藏。
- ↕️ **自定义排序**：主机按 IP / 名称 / 服务数 / 最近发现排序；分类按你设定的顺序。
- 🙈 **隐藏 / 显示**：单个服务可隐藏，一键切换「显示已隐藏」。
- 🔗 **一键跳转**：识别 HTTP/HTTPS 服务，生成可点击链接。
- 💾 **持久化**：主机、服务、扫描历史、所有设置都存 SQLite；设备备注名跨扫描保留。
- ⚙️ **网页内设置**：网段、端口、间隔、分类都能在页面里改，无需重启。

## 快速开始

### 本地运行

```bash
git clone <repo> && cd lan-scout
python3 server.py            # 打开 http://127.0.0.1:8770
```

首次启动自动跑一次扫描。**想要更高的设备发现率**（枚举更多设备、拿到 MAC/厂商）：

```bash
sudo python3 server.py       # 以 root 运行 → nmap 用 ARP 发现 + SYN 扫描
```

### Docker

```bash
# 编辑 docker-compose.yml 里的 LANSCOUT_SUBNET 为你的网段，然后：
docker compose up -d --build
```

> Docker 需要 `network_mode: host` 才能看到局域网，这在 **Linux 宿主机**上有效。
> macOS/Windows 的 Docker Desktop 对 host 网络支持有限，建议在 macOS 上直接 `python3 server.py` 本地运行。

## 使用

- 右上角 **⚙ 设置**：改扫描网段（支持多个，空格/逗号分隔）、端口、自动间隔、`-sV` 开关，以及**分类管理**（增删、改名、配色、排序、整类显示/隐藏、配置归类的端口与服务名）。
- 工具栏：切换 **按主机 / 按分类** 视图、选择排序、勾选 **显示已隐藏的服务**。
- 每个服务旁的 👁 / 🚫 按钮：隐藏或恢复该服务。
- 设备卡片标题处可直接给设备起**备注名**，跨扫描保留。

## 配置（环境变量 — 仅在全新数据库时作为初始值）

运行后这些值由网页设置接管并存入数据库；环境变量只决定首次启动的默认值。

| 变量 | 默认 | 说明 |
|------|------|------|
| `LANSCOUT_SUBNET` | 自动探测 en0 的 /24 | 初始扫描网段，CIDR |
| `LANSCOUT_PORTS` | 一组常见端口 | nmap 端口列表；`-` 表示 top-1000 |
| `LANSCOUT_INTERVAL` | `900` | 自动扫描间隔（秒），0 关闭 |
| `LANSCOUT_SV` | `1` | 服务/版本探测（-sV），`0` 关闭更快 |
| `LANSCOUT_TIMING` | `4` | nmap 计时模板 0-5 |
| `LANSCOUT_HOST` / `LANSCOUT_PORT` | `127.0.0.1` / `8770` | Web 绑定地址 |
| `LANSCOUT_DB` | `./lanscout.db` | SQLite 路径 |

## 发现率 / 权限

- **普通运行**：非特权 TCP connect 扫描（`-sT`），无需 sudo，但会漏掉不响应 ping 的主机，且拿不到 MAC/厂商。
- **特权运行**（`sudo` 或 Docker 带 `NET_RAW`/`NET_ADMIN`）：nmap 自动用 **ARP 发现 + SYN 扫描**，发现更多设备并带出 MAC/厂商。**自己的局域网建议这样跑。**

> 如果只扫到本机一台，多半是网络做了**客户端隔离**（企业 Wi‑Fi/VPN 网段常见）—— 同网段设备二层互不可达，任何工具都扫不到，并非本工具问题。用 `arp -an` 验证：邻居全是 `(incomplete)` 即为隔离。

## 项目结构

见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 许可 & 道德

[MIT](LICENSE)。仅用于扫描**你拥有或已获授权**的网络，请勿用于未授权网络。
