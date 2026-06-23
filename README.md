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

## 发现率 / 权限

设备发现的准确度取决于运行权限：

- **普通运行**（`python3 server.py`）：非特权 TCP connect 扫描（`-sT`），无需 sudo。但会漏掉那些不响应 nmap 默认探测（ping）的主机，MAC/厂商通常也拿不到。
- **特权运行**（`sudo python3 server.py`）：nmap 自动改用 **ARP 主机发现 + SYN 扫描**，这是枚举同网段设备最准的方式，能发现更多设备并带出 MAC 地址和厂商。**建议在自己的局域网里用这种方式。**

> 如果扫描结果只有本机一台，多半是网络做了**客户端隔离**（常见于企业 Wi‑Fi / VPN 网段）——此时同网段设备在二层互相不可达，任何工具都扫不到，并非本工具的问题。可用 `arp -an` 验证：邻居全是 `(incomplete)` 即为隔离。

## 说明

- 仅扫描你自己的局域网。请勿对未授权的网络使用。
