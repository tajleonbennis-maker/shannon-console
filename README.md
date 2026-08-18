# Shannon Console — 攻击面情报平台

将 Shannon 自主渗透测试的扫描结果沉淀为**可查询、可复用、可持续积累**的知识库系统。

## 核心能力

| 能力 | 说明 |
|---|---|
| **扫描数据入库** | scan_runs / findings / agents / events 全量落库（SQLite，零依赖） |
| **组件知识库复用** | 识别技术栈指纹（npm/Python/Go/Rust/Java/PHP/Ruby/C），再次遇到同组件直接命中历史结论，**跳过重复扫描、节省 60%+ token** |
| **知名项目基线库** | 预置 nginx / redis / openssl / fastapi / spring / next.js 等常见项目的攻击面 + CVE 上下文 |
| **实时监控展示** | Web 仪表盘：扫描历史 / 漏洞发现 / 组件库 / 扫描详情（LLM 思考流 + 工具调用） |
| **多生态指纹识别** | package.json / requirements.txt / pyproject.toml / go.mod / Cargo.toml / pom.xml / composer.json / Gemfile / configure.ac / CMakeLists.txt |

## 架构

```
目标靶机（临时/公网）                 数据中枢（自家机器）
┌─────────────────────┐            ┌─────────────────────┐
│ Shannon 扫描执行     │──入库────► │ Shannon Console     │
│ 扫描完 → 重置系统     │            │ SQLite + 展示平台    │
└─────────────────────┘            └─────────────────────┘
```

- **执行与数据分离**：扫描在临时靶机跑，数据永远落在自家数据中枢
- **用完即弃**：目标环境扫描完重装系统，暴露面最小

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

## 组件复用逻辑

```
新仓库 → 读取依赖清单生成组件指纹
      → 与 components 表比对
      → 命中 → 加载 component_insights 历史结论 → 跳过重复代码扫描
      → 未命中 → 完整扫描 → 结论自动入库，下次命中
```

## 项目结构

```
shannon-console/
├── server/
│   ├── shannon_db.py          # SQLite 数据层（6 张表 + 多生态指纹识别）
│   ├── shannon_ingest.py      # 扫描结果自动入库 + pre-recon 报告解析
│   ├── shannon_server.py      # REST API + 前端托管（零依赖）
│   └── known_projects.py      # 知名开源项目基线库（攻击面 + CVE）
├── web/
│   └── index.html             # 数据驱动前端（仪表盘/历史/组件库/发现/详情）
└── scripts/
    ├── deploy.sh              # 一键部署到服务器（systemd）
    ├── surferctl.py           # SurferCloud 临时靶机生命周期管理
    └── surfercloud_api.py     # SurferCloud API 客户端（官方签名算法）
```

## 安全说明

- 服务默认监听 `127.0.0.1`，公网部署请加 `--token` 鉴权
- 所有改造基于 AGPL-3.0，保留上游版权声明
- 仅用于授权目标的渗透测试评估
