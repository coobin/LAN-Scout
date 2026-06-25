# AGENTS.md — LAN Scout 项目概览

本文件为 AI 编码代理提供项目上下文，同时也是开发者的快速参考。

## 项目简介

LAN Scout 是一个**局域网服务发现与导航面板**。后台用 `nmap` 周期性扫描本地网段，将发现的主机、开放端口和服务展示在 Web 界面上，支持一键跳转、自定义分类、Docker 容器管理等功能。

核心设计原则：**零第三方 Python 依赖**，前端单文件，唯一外部程序是 `nmap`。

## 技术栈

| 层         | 技术                                         |
|-----------|----------------------------------------------|
| 后端语言    | Python 3.10+（纯标准库）                       |
| HTTP 服务   | `http.server.ThreadingHTTPServer`（stdlib）    |
| 数据库      | SQLite3（stdlib）                              |
| 网络扫描    | `nmap`（外部系统依赖）                          |
| Docker 探测 | `urllib.request` 直连 Docker API               |
| 并发        | `threading` + `concurrent.futures`（stdlib）   |
| 前端        | 单文件 HTML/CSS/JS，无构建步骤，无框架           |
| 容器化      | Dockerfile（python:3.12-slim）+ docker-compose |

**第三方 Python 包数量：0。** 这是硬性约束，任何新功能都必须用标准库实现。

## 目录结构

```
LAN-Scout/
├── server.py          # (351行) HTTP 服务器、路由、后台扫描调度
├── scanner.py         # (135行) nmap 调用与 XML 输出解析
├── db.py              # (309行) SQLite 持久层（主机/服务/扫描/设置/容器）
├── settings.py        # (170行) 用户可编辑设置，含验证与默认值回退
├── config.py          # (135行) 环境变量读取、种子默认值、子网自动探测
├── docker_probe.py    # (131行) Docker API 查询、容器枚举、CPU/内存统计
├── static/
│   └── index.html     # (1071行) 完整 SPA 仪表板（HTML + CSS + vanilla JS）
├── Dockerfile         # 容器镜像构建
├── docker-compose.yml # 编排配置（host 网络模式）
├── CONTRIBUTING.md    # 贡献指南与架构概览
├── README.md          # 项目文档（中文）
└── LICENSE            # MIT
```

总代码量约 2300 行（Python + HTML/JS），小而完整。

## 模块职责

### `server.py` — 入口与 HTTP 路由

- 程序入口 `main()`：初始化数据库、启动调度线程、触发首次扫描、启动 HTTP 服务
- 所有 API 路由在 `Handler.do_GET` / `do_POST` 中分发
- `run_scan()` 执行一次完整扫描流程（普扫 → 全端口补扫 → Docker 探测 → 持久化）
- `scheduler_loop()` 每 5 秒检查是否到达扫描间隔
- `trigger_scan_async()` 在后台线程中触发扫描，带锁防止并发

### `scanner.py` — nmap 封装

- `scan()` 构建 nmap 命令行并执行，输出 XML 格式
- `_parse_xml()` 解析 nmap XML 为结构化主机/服务字典列表
- 自动检测权限：root 用 `-sS`（SYN 扫描），普通用户用 `-sT`（TCP connect）
- `nmap_available()` / `is_scanning()` 状态查询

### `db.py` — 数据持久化

- `init()` 创建所有表（幂等）
- `save_scan_result()` 合并更新主机和服务（保留用户标注的 label/note）
- `get_hosts()` 返回完整状态（主机 + 服务 + 容器），供前端渲染
- `save_single_docker_host()` 存储指定 Docker 主机的容器信息
- 线程安全：每次调用创建新连接

### `settings.py` — 运行时设置

- `get()` 从数据库读取设置，未存储则使用 `config.py` 中的种子默认值
- `update()` 验证并更新设置，支持部分更新
- 管理分类（categories）的校验与清理
- `_TARGET_RE` 正则用于验证 IP/主机名格式

### `config.py` — 初始配置

- 从 `LANSCOUT_*` 环境变量读取初始值
- 自动探测本机子网（通过 `ip route` 或 `ifconfig`）
- 定义默认服务分类（管理面板、媒体、存储、开发工具等）及端口/服务名映射

### `docker_probe.py` — Docker 集成

- `probe()` 对给定主机列表查询 Docker API（2375/2376 端口）
- `_query()` 获取容器列表，`_fetch_stats()` 并发获取 CPU/内存统计
- 支持 HTTP (2375) 和 HTTPS (2376) 两种端口

### `static/index.html` — 前端仪表板

- 纯 vanilla JS 单页应用，无构建步骤
- 两种视图：导航视图（按分类）、主机视图（按设备）
- 功能：全局搜索、分类过滤、排序、服务隐藏/重命名、主机备注
- Docker 容器管理（启动/停止）
- 亮色/暗色主题（localStorage 持久化）
- CSS 变量实现主题切换

## API 端点

### GET

| 路径          | 说明                                     |
|--------------|------------------------------------------|
| `/api/state` | 返回完整应用状态（设置、扫描状态、主机列表） |
| `/`          | 提供静态文件（index.html）                 |

### POST

| 路径                          | 说明                   |
|------------------------------|------------------------|
| `/api/scan`                  | 触发一次后台扫描         |
| `/api/settings`              | 更新运行时设置           |
| `/api/docker/add`            | 添加手动 Docker 主机     |
| `/api/docker/control`        | 控制容器（启动/停止）     |
| `/api/service/add`           | 添加自定义服务           |
| `/api/host/<ip>`             | 更新主机标签/备注        |
| `/api/host/<ip>/delete_service` | 隐藏/删除指定服务     |

## 数据库表结构

```sql
hosts      (ip PK, mac, vendor, hostname, label, note, is_up, first_seen, last_seen)
services   (ip+port+protocol PK, name, product, version, last_seen, is_custom)
scans      (id PK, started_at, finished_at, subnet, host_count, error)
settings   (key PK, value)  -- 存储 JSON 序列化的设置
containers (ip+name PK, image, state, status, ports[JSON], last_seen, cpu, mem)
```

## 扫描工作流

1. **调度线程** 每 5 秒检查扫描间隔是否到达
2. **扫描执行**（手动或定时触发）：
   - 以配置的目标/端口/计时运行 nmap → 解析 XML
   - 若 `full_targets` 非空：对指定主机做 `-Pn` 全端口补扫，合并结果
   - 若发现 Docker 端口（2375/2376）：查询 Docker API，获取容器及统计
   - 若有手动添加的 Docker 主机：额外查询
   - 所有结果持久化到 SQLite
3. **前端轮询** `/api/state` 实时刷新界面
4. **扫描锁** 保证同时只有一个扫描在运行

## 权限与扫描模式

- **普通运行** (`python3 server.py`)：TCP connect 扫描 (`-sT`)，无需 sudo，发现率较低，无 MAC/厂商信息
- **特权运行** (`sudo python3 server.py`)：ARP 发现 + SYN 扫描 (`-sS`)，发现更多设备，带 MAC/厂商

## 环境变量（仅首次启动生效）

| 变量                | 默认值          | 说明                          |
|--------------------|-----------------|-----------------------------|
| `LANSCOUT_SUBNET`  | 自动探测         | 扫描网段（CIDR）               |
| `LANSCOUT_PORTS`   | 常见端口列表      | nmap 端口列表；`-` 为 top-1000 |
| `LANSCOUT_INTERVAL`| `900`           | 自动扫描间隔（秒），0 关闭      |
| `LANSCOUT_SV`      | `1`             | 服务/版本探测 (`-sV`)          |
| `LANSCOUT_TIMING`  | `4`             | nmap 计时模板 (0-5)            |
| `LANSCOUT_HOST`    | `127.0.0.1`     | HTTP 绑定地址                  |
| `LANSCOUT_PORT`    | `8770`          | HTTP 绑定端口                  |
| `LANSCOUT_DB`      | `./lanscout.db` | SQLite 数据库路径              |

运行后设置由网页接管，存入数据库，环境变量不再生效。

## 开发指南

```bash
# 本地开发
python3 server.py            # http://127.0.0.1:8770
sudo python3 server.py       # 特权模式，发现率更高

# Docker
docker compose up -d --build
```

- 无编译步骤、无包管理器、无构建工具
- 修改 Python 文件后重启进程即可
- 修改 `static/index.html` 后刷新浏览器即可
- 不要提交 `lanscout.db` 或 `data/` 目录下的文件

## 测试

目前无自动化测试框架。欢迎在 `tests/` 目录下添加 `unittest` 模块。

## 代码风格

- 无强制格式化工具，保持与现有代码风格一致
- 中文优先的 UI 标签和注释
- 变量/函数命名使用 snake_case
- 私有函数以 `_` 前缀

## 注意事项

- 仅用于你拥有或已获授权的网络，请勿用于未授权网络扫描
- Docker 需要 `network_mode: host` 才能访问局域网（仅 Linux 有效）
- macOS/Windows Docker Desktop 不支持 host 网络模式，建议直接本地运行
