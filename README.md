# Shannon Console — 攻击面情报平台

将 Shannon 自主渗透测试的扫描结果沉淀为**可查询、可复用、可持续积累**的知识库系统，并提供**攻击方 / 防守方双视角**观测能力。

## 核心能力

| 能力 | 说明 |
|---|---|
| **扫描数据入库** | scan_runs / findings / agents / events 全量落库（SQLite，零依赖） |
| **组件知识库复用** | 识别技术栈指纹，再次遇到同组件直接命中历史结论，**跳过重复扫描、节省 60%+ token** |
| **知名项目基线库** | 预置 nginx / redis / openssl / fastapi / spring / next.js 等常见项目的攻击面 + CVE 上下文 |
| **防守方观测** | 目标机安装轻量传感器（auditd + 访问日志 + 抓包），记录 shannon 攻击行为，回传数据中枢 |
| **双视角情报** | 攻击方视角（agent 日志）+ 防守方视角（目标机观测事件）对照分析 |
| **多生态指纹识别** | npm / Python / Go / Rust / Java / PHP / Ruby / C 八种生态 |

## 架构

```
┌─────────────────────┐         ┌─────────────────────┐
│ 目标靶机（公网）      │         │ 数据中枢（自家机器）  │
│ 目标应用 + 传感器    │──拉取──► │ Shannon Console     │
│ (auditd/tcpdump)    │  pull   │ SQLite + 展示平台    │
└─────────────────────┘         └─────────────────────┘
```

- **执行与数据分离**：扫描在目标机执行，数据永远落在自家数据中枢
- **pull 模式回传**：目标机在公网、中枢在内网时，由中枢主动 SSH 拉取观测事件（见 `server/pull_defender.py`）
- **用完即弃**：目标环境扫描完可重装系统，暴露面最小

## 双视角观测

```
攻击方视角（shannon agent 日志）        防守方视角（目标机传感器）
┌──────────────────────────┐         ┌──────────────────────────┐
│ LLM 思考 / 工具调用       │         │ auditd 系统调用/文件访问   │
│ pre-recon / recon 阶段    │  对照   │ 应用访问日志(HTTP请求)     │
│ 成本 / token 消耗         │         │ 攻击特征标签(SQLi/XSS等)   │
└──────────────────────────┘         └──────────────────────────┘
```

三层监控（`server/target_sensor.py` + `scripts/install_target_sensor.sh`）：

1. **L1 系统行为审计** — auditd 记录进程执行(execve)、敏感文件读写（/etc/passwd、/etc/shadow、应用目录）
2. **L2 应用访问日志** — 采集 nginx/FastAPI/gunicorn access log，记录 shannon 打过的每个 HTTP 请求
3. **L3 网络抓包** — tcpdump 被动监听目标端口（按需开启）

## 快速开始

```bash
# 1. 启动后端（零第三方依赖，Python 3.8+）
python3 server/shannon_server.py --host 0.0.0.0 --port 8788 --db /path/to/shannon.db

# 2. 浏览器打开
# http://<host>:8788/

# 3. 扫描结果入库（workspace = shannon 的扫描工作区目录）
curl -X POST http://<host>:8788/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"workspace":"/path/to/workspace","repo_dir":"/path/to/target-repo"}'
```

### 目标机安装传感器（防守方观测）

```bash
# 在目标机上执行（需要 root）
sudo bash scripts/install_target_sensor.sh <中枢IP:端口>

# 数据中枢定时拉取（cron 或 systemd）
python3 server/pull_defender.py --interval 30
```

## API 端点

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/stats` | 统计概览 |
| GET | `/api/scans` | 扫描列表 |
| GET | `/api/scans/<id>` | 扫描详情（含 agents/findings/events） |
| GET | `/api/components` | 组件库 |
| GET | `/api/insights` | 组件分析结论 |
| GET | `/api/known-projects` | 知名项目基线库 |
| GET | `/api/findings` | 漏洞发现 |
| GET | `/api/defender-events` | 防守方观测事件 |
| GET | `/api/defender-stats` | 防守方统计 |
| POST | `/api/ingest` | 触发扫描结果入库 |
| POST | `/api/defender-events` | 目标机传感器事件回传 |

## 组件复用逻辑

```
新仓库 → 读取依赖清单生成组件指纹（8 生态）
      → 与 components 表比对
      → 命中 → 加载 component_insights 历史结论 → 跳过重复代码扫描
      → 未命中 → 完整扫描 → 结论自动入库，下次命中
```

## 项目结构

```
shannon-console/
├── server/
│   ├── shannon_db.py          # SQLite 数据层（7 张表 + 多生态指纹识别）
│   ├── shannon_ingest.py      # 扫描结果自动入库 + pre-recon 报告解析
│   ├── shannon_server.py      # REST API + 前端托管（零依赖）
│   ├── known_projects.py      # 知名开源项目基线库（攻击面 + CVE）
│   ├── target_sensor.py       # 目标机安全监控采集器（三层观测）
│   └── pull_defender.py       # 数据中枢主动拉取观测事件（pull 模式）
├── web/
│   └── index.html             # 数据驱动前端（仪表盘/历史/组件库/发现/防守视角）
└── scripts/
    ├── deploy.sh              # 一键部署到服务器（systemd）
    ├── install_target_sensor.sh # 目标机一键安装安全监控
    ├── surferctl.py           # SurferCloud 临时靶机生命周期管理
    └── surfercloud_api.py     # SurferCloud API 客户端（官方签名算法）
```

## 安全说明

- 服务默认监听 `127.0.0.1`，公网部署请加 `--token` 鉴权
- 传感器只**记录不拦截**，不改变目标应用行为
- 凭据存于 `~/.ssh/shannon_hosts.json`（权限 600），不写入代码
- 所有改造基于 AGPL-3.0，保留上游版权声明
- 仅用于授权目标的渗透测试评估
