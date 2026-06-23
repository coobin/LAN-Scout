# LAN Scout

局域网服务发现 + 导航页。后台用 `nmap` 周期性扫描本地网段，把发现的主机、开放端口和服务列在一个网页上，Web 服务还能一键点击跳转。

零第三方依赖：Python 标准库 + SQLite，前端单文件。

## 依赖

- Python 3.10+
- `nmap`（macOS：`brew install nmap`）

## 运行

```bash
cd lan-scout
python3 server.py
```

打开 http://127.0.0.1:8770 。首次启动会自动跑一次扫描。

## 功能

- **自动扫描**：默认每 15 分钟扫一次（`LANSCOUT_INTERVAL`，秒；设 0 关闭）。
- **手动扫描**：页面右上角「立即扫描」。
- **服务跳转**：识别为 HTTP/HTTPS 的端口生成可点击链接。
- **持久化**：结果存 SQLite（`lanscout.db`）。给设备起的「备注名」跨扫描保留。
- **搜索**：按 IP / 名称 / 服务 / 厂商过滤。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|------|------|------|
| `LANSCOUT_SUBNET` | 自动探测 en0 的 /24 | 扫描网段，CIDR |
| `LANSCOUT_PORTS` | 一组常见端口 | nmap 端口列表；`-` 表示 top-1000 |
| `LANSCOUT_INTERVAL` | `900` | 自动扫描间隔（秒），0 关闭 |
| `LANSCOUT_SV` | `1` | 服务/版本探测（-sV），`0` 关闭更快 |
| `LANSCOUT_TIMING` | `4` | nmap 计时模板 0-5 |
| `LANSCOUT_HOST` / `LANSCOUT_PORT` | `127.0.0.1` / `8770` | Web 绑定地址 |

## 说明

- 用的是非特权 TCP connect 扫描（`-sT`），无需 sudo；因此 MAC 地址/厂商只有在同一二层网段、系统 ARP 缓存命中时才会显示。
- 仅扫描你自己的局域网。请勿对未授权的网络使用。
