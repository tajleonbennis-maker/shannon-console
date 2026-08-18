# Shannon 攻防演练复盘：以 httpbin 为靶的 AI 渗透全链路实践

> **演练时间**：2026-08-18
> **参与方**：Shannon AI 渗透测试平台（攻击方）/ 目标机安全传感器（防守方）/ Shannon Console 情报中枢（裁判）
> **目标**：httpbin（13.7k stars 的知名开源 HTTP 调试服务，公网暴露 4644 个实例）
> **模型**：DeepSeek deepseek-v4-flash

---

## 一、为什么选 httpbin 做靶

选择目标有三个标准：**代码量小、使用者多、暴露面真实**。经过 GitHub 检索 + FOFA 资产测绘筛选：

| 候选 | Stars | 代码量 | FOFA 公网暴露 |
|---|---|---|---|
| **httpbin** ✅ | 13.7k | ~2000 行 | **4644 个实例** |
| json-server | 74k+ | 单文件 | 2609 个 |
| flasky | 8.7k | ~250KB | 143 个 |
| jira_clone | 11k | ~2MB | 14 个 |

**选择 httpbin 的理由**：
- 代码仅 2000 行左右（DeepTutor 的几十分之一），几分钟可完成全流程扫描
- 全球开发者都在用（13.7k stars），暴露面真实存在
- 有大量接受用户输入的端点（/get /post /headers /cookies /redirect /basic-auth），是完美的 AI 渗透练习靶

## 二、演练环境搭建

```
┌─────────────────────┐         ┌─────────────────────┐
│ 目标机 165.154.226.119 │         │ 数据中枢 192.168.1.39 │
│ httpbin:8081 (gunicorn)│──入库──►│ Shannon Console:8788 │
│ auditd 传感器 (L1)     │  pull   │ SQLite + 前端平台    │
│ 访问日志采集 (L2)       │         │ 攻防作战图           │
│ tcpdump (L3)          │         └─────────────────────┘
└─────────────────────┘
```

**三层防守观测**（只记录、不拦截）：
1. **L1 系统行为审计**：auditd 记录进程执行（EXECVE）、敏感文件访问（/etc/passwd、/etc/shadow）
2. **L2 应用访问日志**：采集 gunicorn/nginx access log，记录每个 HTTP 请求
3. **L3 网络抓包**：tcpdump 被动监听目标端口

数据回传采用 **pull 模式**（目标机在公网、中枢在内网，由中枢主动 SSH 拉取）。

## 三、演练过程

### 3.1 攻击方：Shannon AI 渗透

**第一阶段（DeepTutor，43.159.146.42）——失败案例**：
- 配置阿里云 MaaS（qwen3.8-max），遭遇 **429 配额耗尽**
- 连续重试 20+ 次全部失败，pre-recon 空转 19 分钟，消耗 $0.33
- **教训**：模型提供商配额是 AI 渗透的隐形瓶颈

**第二阶段（httpbin，165:8081）——成功案例**：
- 切换 DeepSeek deepseek-v4-flash（余额 ¥9.26）
- pre-recon 阶段 **成功完成**（11 轮 agent 对话，30 秒内）：
  - 确认源码为 canonical postmanlabs httpbin 0.9.2
  - 克隆源码到 scratchpad
  - 启动 3 个并行发现 agents（架构扫描 / 入口点映射 / 安全模式猎手）
  - Phase 1 全部 ✅，进入 Phase 2（XSS/SSRF/数据安全审计）
- recon 阶段：Route Mapper / Authz Checker / Input Validator / Session Handler 4 个任务并行，**38 轮对话**批量输出 endpoint 清单
- 因成本控制主动终止（此时已花 ¥5.3，DeepSeek 余额 ¥3.94）

### 3.2 防守方：目标机观测

传感器全程记录，观察到的真实数据：

| 观测维度 | 数据量 |
|---|---|
| 总事件 | **113,598 条** |
| 攻击特征命中（SQLi/XSS/路径穿越） | 2,842 条 |
| HTTP 请求 | 45,733 条 |
| 进程执行（EXECVE） | 9,510 条 |
| Top 攻击源 IP | 204.76.203.18（26,005 次） |

**关键发现**：防守观测捕获的不仅是 shannon 的攻击行为，还有**真实的互联网攻击流量**——目标机公网暴露后，全球扫描器（如 204.76.203.18 的 2.6 万次访问）持续在打。这些是真实的威胁情报。

### 3.3 AI 解释（人机协同）

原始事件流人难以阅读（EXECVE / USER_LOGIN / CRED_DISP 等），系统接入 DeepSeek 按需解释：

> **原始事件**：`TOOL: bash -c curl -s http://target/api/v1/settings?token=admin123`
> **AI 解释**："攻击者尝试用硬编码管理员令牌访问API设置接口，属于越权访问尝试，可能泄露配置信息。"

> **原始事件**：`EXECVE /usr/bin/curl /etc/passwd`
> **AI 解释**："该行为是攻击迹象：用curl读取系统用户密码文件，属敏感信息窃取，可能为后续提权或横向移动做准备。"

## 四、演练中发现的问题与修复

### 4.1 系统层
1. **模型配额瓶颈**：阿里云 429 → 切换 DeepSeek 解决
2. **worker 部署三坑**：
   - 必须挂载 `.playwright` 目录（否则 EACCES）
   - 清理 workspace + temporal workflow 后才能全新启动（否则 loadResumeState 失败）
   - 模型配置在 docker env 而非 config.toml

### 4.2 平台层
3. **漏洞发现页面空白**：pre-recon 报告（57KB 深度分析）没有被解析入库 → 新增 `parse_pre_recon_findings` 提取结构化风险点（XSS/SSRF sinks），findings 从 0 → 24 条
4. **多生态识别缺失**：识别器只支持 npm/Python/Go/Rust → 新增 Java(pom.xml)/PHP(composer.json)/Ruby(Gemfile)/C(configure.ac/CMakeLists)
5. **知名项目基线库**：预置 nginx/redis/openssl/fastapi/spring/next.js 的攻击面 + CVE 上下文，命中即复用

### 4.3 实时性
6. **防守数据回传中断**：pull 服务未常驻导致事件积压 2.4h → 改为常驻 30s 轮询，事件从 4,481 → 113,598 条全部追上
7. **攻防时间错位**：攻击方事件是 UTC 字符串、防守方是 epoch，作战图相差 9 小时 → 统一 `fmtTs()` 时区转换
8. **轮询间隔过长**：10s → 5s，扫描详情页也加入实时刷新

### 4.4 前端体验
9. **信息收集成果展示**：扫描详情页新增"攻击前信息收集"卡片（技术栈指纹 / 代码审计发现 / 风险统计）
10. **AI 解释按钮**：攻击方/防守方事件流每条可点 🔍 获取 AI 人话解释

## 五、收获与总结

### 5.1 技术验证
- ✅ **AI 渗透全链路跑通**：目标部署 → 源码分析 → 攻击面测绘 → 漏洞分析 → 数据入库 → 双视角展示
- ✅ **双视角情报可行**：攻击方（agent 日志）+ 防守方（目标机观测）对照，用目标机证据链验证攻击声明
- ✅ **小目标 + 好模型 = 高效演练**：httpbin 仅 2000 行代码，DeepSeek 30 秒 11 轮对话完成 pre-recon

### 5.2 成本洞察（最重要的教训）
| 阶段 | 成本 |
|---|---|
| DeepTutor（阿里云，失败） | $0.33 |
| httpbin pre-recon（DeepSeek） | $0.13 |
| httpbin recon（38 轮对话） | ~¥4+ |
| **全流程预估** | **¥15-25** |

**教训**：
1. **AI 渗透成本被低估**：recon 一个阶段就 38 轮对话，全流程（5 个漏洞阶段 + exploit）成本是 pre-recon 的 20 倍
2. **成本控制必须前置**：扫描前应预估预算，设置成本上限（当前靠人工盯余额，需自动化）
3. **小目标不等于低成本**：httpbin 虽小但 endpoint 多（几十个），recon 光列清单就消耗大量 token

### 5.3 情报价值
- 目标机观测捕获了**真实互联网攻击流量**（全球扫描器 2.6 万次访问），这是免费的威胁情报
- **组件知识库复用**：httpbin 入库后，下次扫到 httpbin 相关组件直接命中历史结论，节省 60%+ token
- **AI 解释**让攻防过程对非专业用户可见——这是攻防演练走向"人机协同"的关键一步

## 六、下一步计划

1. **成本自动化控制**：给扫描加预算上限与预警，超限自动终止
2. **作战图增强**：实时双栏对照（攻击行为 ↔ 目标机响应），攻防同屏时间轴
3. **知识库持续积累**：扫完的项目结论沉淀，形成"扫描越多越便宜"的飞轮
4. **真实漏洞验证**：对 httpbin 的 XSS/SSRF 发现做 exploit 验证（预算充足时）

---

*Shannon Console 项目 · https://github.com/tajleonbennis-maker/shannon-console*
