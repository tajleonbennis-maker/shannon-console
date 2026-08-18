#!/usr/bin/env python3
"""
shannon_ingest.py — 扫描结果自动入库器

从 shannon workspace 读取：
  .shannon/session.json        扫描主记录 + agents 明细
  .shannon/workflow.log        事件流（LLM/TOOL/AGENT/PHASE）
  .shannon/agents/*.log        agent 详细 JSON 事件流（LLM 思考/工具参数/结果）
  .shannon/deliverables/*.md   交付物（pre_recon 等，用于组件识别与 insights）
  /repos/<target>/             目标仓库（组件指纹识别）

产出：
  - scan_runs / findings / agents / events 入库
  - components 组件指纹识别 + component_insights 分析结论（复用缓存）

用法：
  python3 shannon_ingest.py <workspace_dir> [--db shannon.db] [--repo-dir /repos/x] [--scan-id 可选]
"""
import argparse
import glob
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shannon_db import ShannonDB, identify_components


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def find_file(base, *rel):
    for c in [os.path.join(base, *rel), os.path.join(base, ".shannon", *rel)]:
        if os.path.exists(c):
            return c
    return None


def parse_workflow_log(path):
    """解析 workflow.log → 事件列表。"""
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError:
        return events
    for line in lines:
        line = line.strip()
        if not line or line.startswith("="):
            continue
        m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[([\w-]+)\] \[(\w+)\](?:: (.*))?", line)
        if m:
            events.append({"ts": m.group(1), "agent": m.group(2),
                           "etype": m.group(3), "detail": (m.group(4) or "")[:2000]})
    return events


def parse_agent_log(path):
    """解析 agents/*.log 的 JSON 行 → 精选事件（LLM 思考/工具调用/错误）。"""
    events = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                t = ev.get("type")
                data = ev.get("data", {}) or {}
                ts = (ev.get("timestamp") or "")[:19].replace("T", " ")
                agent = data.get("agentName", "")
                if t == "tool_start":
                    detail = f"TOOL {data.get('toolName','')} params={json.dumps(data.get('parameters',{}), ensure_ascii=False)[:600]}"
                    events.append({"ts": ts, "agent": agent, "etype": "TOOL", "detail": detail})
                elif t == "tool_end":
                    res = data.get("result", {})
                    txt = ""
                    if isinstance(res, dict) and res.get("content"):
                        for c in res["content"]:
                            if isinstance(c, dict) and c.get("text"):
                                txt += c["text"]
                    detail = f"TOOL-RESULT {txt[:400]}"
                    events.append({"ts": ts, "agent": agent, "etype": "TOOL_RESULT", "detail": detail})
                elif t == "llm_response":
                    txt = data.get("text", "") or data.get("message", "") or ""
                    if isinstance(txt, dict):
                        txt = txt.get("content", "") or ""
                    detail = f"LLM {str(txt)[:600]}"
                    events.append({"ts": ts, "agent": agent, "etype": "LLM", "detail": detail})
                elif t == "error":
                    detail = f"ERROR {data.get('message','')[:400]}"
                    events.append({"ts": ts, "agent": agent, "etype": "ERR", "detail": detail})
    except OSError:
        pass
    return events


def read_repo_files(repo_dir, max_files=60, max_size=300_000):
    """读取仓库关键文件用于组件指纹识别。"""
    files = {}
    if not repo_dir or not os.path.isdir(repo_dir):
        return files
    targets = ["package.json", "requirements.txt", "pyproject.toml",
               "go.mod", "Cargo.toml", "Pipfile", "composer.json",
               "pom.xml", "configure.ac", "configure.in", "CMakeLists.txt", "Gemfile"]
    for t in targets:
        for root, _, _ in os.walk(repo_dir):
            # 跳过常见排除目录，加速且避免误识别依赖目录
            if any(seg in root.split(os.sep) for seg in ("node_modules", "vendor", ".git", "dist", "build")):
                continue
            p = os.path.join(root, t)
            if os.path.exists(p) and os.path.getsize(p) < max_size:
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        files[os.path.relpath(p, repo_dir)] = f.read()
                except OSError:
                    pass
                break
        if len(files) >= max_files:
            break
    return files


def parse_pre_recon_findings(content, path=""):
    """从 pre-recon 交付物解析结构化风险点。

    识别两类模式：
      1. "- **标题** at `file:line` — HIGH: 描述"  (XSS/SSRF Sinks 章节)
      2. "- **标题:** 描述 (path:line) (HIGH)"  (其他章节)
    返回 [{type, severity, location, summary}]
    """
    findings = []
    sev_map = {"critical": "critical", "high": "high", "medium": "med", "low": "low"}

    # 模式1: - **标题** at `path:line` — SEVERITY: desc
    pat1 = re.compile(
        r"^[-*]\s+\*\*(?P<title>[^*]+?)\*\*\s+at\s+`(?P<loc>[^`]+?`?\s*\([^)]*\)|\S+?:\d+|\S+)`\s*[—-]\s*(?P<sev>CRITICAL|HIGH|MEDIUM|LOW)(?:[^\w]|$)(?P<desc>.*)",
        re.M | re.I)
    # 模式2: - **标题:** desc (path:line) (HIGH)
    pat2 = re.compile(
        r"^[-*]\s+\*\*(?P<title>[^*]+?):\*\*\s*(?P<desc>.*?)\s*\((?P<loc>[^)]+?:\d+)\)\s*\((?P<sev>CRITICAL|HIGH|MEDIUM|LOW)\)",
        re.M | re.I)
    # 模式3: 宽松 - **标题** at `path` — desc (含 HIGH 关键词)
    pat3 = re.compile(
        r"^[-*]\s+\*\*(?P<title>[^*]+?)\*\*\s+at\s+`(?P<loc>[^`]+?)`\s*[—-]\s*(?P<sev>CRITICAL|HIGH|MEDIUM|LOW)(?P<desc>.*)",
        re.M | re.I)

    for pat in (pat1, pat3):
        for m in pat.finditer(content):
            sev = m.group("sev").lower()
            desc = (m.group("desc") or "").strip()
            loc = m.group("loc").strip()
            title = m.group("title").strip()
            # 去掉行号后缀（`xxx.py:123` → xxx.py）
            loc_file = loc.split(":")[0].strip("` ")
            summary = f"{title}: {desc}"[:500]
            findings.append({"type": "code_sink", "severity": sev_map.get(sev, "info"),
                             "location": loc_file, "summary": summary})

    for m in pat2.finditer(content):
        sev = m.group("sev").lower()
        findings.append({"type": "code_sink", "severity": sev_map.get(sev, "info"),
                         "location": m.group("loc").strip(), "summary": f"{m.group('title')}: {m.group('desc')}"[:500]})

    return findings


def extract_findings_from_deliverables(ws_dir):
    """从 deliverables/*.md 提取 findings（pre-recon 结构化风险点 + 技术栈）。"""
    findings = []
    deliv_dir = os.path.join(ws_dir, ".shannon", "deliverables")
    if not os.path.isdir(deliv_dir):
        return findings
    for path in sorted(glob.glob(os.path.join(deliv_dir, "*.md"))):
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except OSError:
            continue
        base = os.path.basename(path)
        if "pre_recon" in base or "recon" in base:
            # 技术栈摘要
            m = re.findall(r"(FastAPI|Django|Flask|Next\.js|React|Vue|Express|Spring|Go|Rust|SQLite|PostgreSQL|MongoDB|Redis|JWT|OAuth|LLaMA|LlamaIndex|FAISS)", content)
            if m:
                findings.append({"type": "tech_stack", "severity": "info",
                                 "location": path, "summary": "技术栈: " + ", ".join(dict.fromkeys(m))[:300]})
            # 结构化风险点
            for fd in parse_pre_recon_findings(content, path):
                findings.append(fd)
    return findings


def ingest(workspace, db_path, repo_dir=None, scan_id_override=None):
    """主入口：把 workspace 数据入库，返回摘要。"""
    ws_dir = os.path.abspath(workspace)
    session = load_json(find_file(ws_dir, "session.json")) or {}
    sess = session.get("session") or {}
    metrics = session.get("metrics") or {}

    scan_id = scan_id_override or sess.get("id") or f"{os.path.basename(ws_dir)}_scan"
    target = sess.get("webUrl") or ""
    status = sess.get("status") or "unknown"
    model = (metrics.get("agents") or {}).get("pre-recon", {}).get("model", "")
    cost = metrics.get("total_cost_usd", 0)
    created = str(sess.get("createdAt", ""))[:19]

    db = ShannonDB(db_path)

    # 1. scan_runs
    db.upsert_scan(scan_id, target_url=target, status=status, model=model,
                   total_cost=cost, created_at=created, workspace=ws_dir)

    # 2. agents
    agents_map = metrics.get("agents") or {}
    for name, a in agents_map.items():
        if not isinstance(a, dict):
            continue
        for at in a.get("attempts") or []:
            if not isinstance(at, dict):
                continue
            db.add_agent(scan_id, name, at.get("attempt_number", 1),
                         "success" if at.get("success") else "failed",
                         at.get("duration_ms", 0), at.get("cost_usd", 0),
                         at.get("turns", 0), at.get("input_tokens", 0),
                         at.get("output_tokens", 0), at.get("model", ""))

    # 3. workflow.log 事件
    wf = find_file(ws_dir, "workflow.log")
    if wf:
        for ev in parse_workflow_log(wf):
            db.add_event(scan_id, ev["ts"], ev["agent"], ev["etype"], ev["detail"])

    # 4. agents/*.log 详细事件
    agents_dir = os.path.join(ws_dir, ".shannon", "agents")
    if os.path.isdir(agents_dir):
        for path in glob.glob(os.path.join(agents_dir, "*.log"))[:20]:
            for ev in parse_agent_log(path):
                db.add_event(scan_id, ev["ts"], ev["agent"], ev["etype"], ev["detail"])

    # 5. deliverables → findings 线索
    for fd in extract_findings_from_deliverables(ws_dir):
        db.add_finding(scan_id, component="", vuln_type=fd["type"], severity=fd["severity"],
                       location=fd["location"], summary=fd["summary"])

    # 6. 组件指纹识别（从 repo 目录）
    repo_files = read_repo_files(repo_dir)
    components = identify_components(repo_files)
    for c in components:
        db.upsert_component(c["name"], c["version"], c["category"], c["file_path"], scan_id)

    # 7. 组件 insights（未命中历史 → 从 pre-recon 交付物生成初版结论）
    insight_files = {}
    deliv_dir = os.path.join(ws_dir, ".shannon", "deliverables")
    if os.path.isdir(deliv_dir):
        for path in glob.glob(os.path.join(deliv_dir, "*.md")):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    insight_files[os.path.basename(path)] = f.read()
            except OSError:
                pass
    combined = "\n".join(insight_files.values())
    # 知名项目基线库命中 → 写入历史结论
    try:
        from known_projects import match_known_project
        known_hits = match_known_project(components)
        for kh in known_hits:
            info = kh["info"]
            summary = f"[基线库] {info['summary']}"
            risk_tags = [f"{s[:14]}" for s in info["attack_surfaces"][:3]] or ["待分析"]
            db.upsert_insight(kh["name"], "any", summary,
                              json.dumps(info.get("attack_surfaces", []), ensure_ascii=False),
                              json.dumps(info.get("known_config_risks", []), ensure_ascii=False),
                              json.dumps(risk_tags, ensure_ascii=False), scan_id)
    except ImportError:
        known_hits = []
    for c in components:
        if not db.get_insight(c["name"], c["version"]):
            summary = "首次扫描入库（来源: %s）" % scan_id
            risk_tags = []
            low = combined.lower()
            if "ssrf" in low: risk_tags.append("SSRF")
            if "auth" in low or "authentication" in low: risk_tags.append("Auth")
            if "injection" in low or "sql" in low: risk_tags.append("Injection")
            if "jwt" in low: risk_tags.append("JWT")
            if "cors" in low: risk_tags.append("CORS")
            if not risk_tags: risk_tags = ["待分析"]
            db.upsert_insight(c["name"], c["version"], summary,
                              "[]", "[]", json.dumps(risk_tags, ensure_ascii=False), scan_id)

    stats = db.stats()
    db.close()
    return {"scan_id": scan_id, "target": target, "status": status,
            "components": len(components), "known_hits": len(known_hits), **stats}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Shannon 扫描结果自动入库")
    parser.add_argument("workspace", help="workspace 目录")
    parser.add_argument("--db", default="shannon.db", help="SQLite 路径")
    parser.add_argument("--repo-dir", default=None, help="目标仓库目录（组件指纹识别）")
    parser.add_argument("--scan-id", default=None, help="指定 scan_id（默认取 session.id）")
    args = parser.parse_args()
    result = ingest(args.workspace, args.db, args.repo_dir, args.scan_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
