#!/usr/bin/env python3
"""
shannon_db.py — Shannon 扫描结果数据层（SQLite）

表结构：
  scan_runs           扫描主记录
  findings            漏洞发现
  agents              agent 执行明细
  components          组件指纹（识别出的技术栈/依赖）
  component_insights  组件历史分析结论（复用缓存）
  events              agent 事件流（LLM 思考/工具调用）

所有写入用事务，读操作并发安全（WAL 模式）。
零第三方依赖，Python 3.8+。
"""
import json
import os
import re
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id            TEXT PRIMARY KEY,
    target_url    TEXT,
    status        TEXT,
    model         TEXT,
    total_cost    REAL DEFAULT 0,
    total_input_tokens   INTEGER DEFAULT 0,
    total_output_tokens  INTEGER DEFAULT 0,
    created_at    TEXT,
    finished_at   TEXT,
    workspace     TEXT,
    summary       TEXT
);
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    component   TEXT,
    vuln_type   TEXT,
    severity    TEXT,
    location    TEXT,
    summary     TEXT,
    steps       TEXT,
    raw_json    TEXT,
    created_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE TABLE IF NOT EXISTS agents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id      TEXT,
    agent_name   TEXT,
    attempt      INTEGER,
    status       TEXT,
    duration_ms  INTEGER,
    cost_usd     REAL,
    turns        INTEGER,
    input_tokens INTEGER,
    output_tokens INTEGER,
    model        TEXT,
    created_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_agents_scan ON agents(scan_id);
CREATE TABLE IF NOT EXISTS components (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT,
    version     TEXT,
    category    TEXT,
    file_path   TEXT,
    first_seen_scan TEXT,
    seen_count  INTEGER DEFAULT 1,
    last_seen   TEXT,
    UNIQUE(name, version)
);
CREATE TABLE IF NOT EXISTS component_insights (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    component    TEXT,
    version      TEXT,
    summary      TEXT,
    entry_points TEXT,
    data_flows   TEXT,
    risk_tags    TEXT,
    source_scan  TEXT,
    created_at   TEXT,
    UNIQUE(component, version)
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT,
    ts          TEXT,
    agent       TEXT,
    etype       TEXT,
    detail      TEXT,
    raw         TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id, ts);
CREATE TABLE IF NOT EXISTS defender_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL,
    source      TEXT,
    layer       TEXT,
    etype       TEXT,
    process     TEXT,
    path        TEXT,
    src_ip      TEXT,
    method      TEXT,
    url         TEXT,
    status      TEXT,
    tags        TEXT,
    raw         TEXT,
    created_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_def_ts ON defender_events(ts);
CREATE INDEX IF NOT EXISTS idx_def_type ON defender_events(etype);
"""


class ShannonDB:
    def __init__(self, db_path):
        self.db_path = db_path
        os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def close(self):
        self.conn.close()

    # ---------- scan_runs ----------
    def upsert_scan(self, scan_id, target_url=None, status=None, model=None, total_cost=None,
                    input_tokens=None, output_tokens=None, created_at=None, workspace=None, summary=None):
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO scan_runs (id, target_url, status, model, total_cost,
                                          total_input_tokens, total_output_tokens, created_at, workspace, summary)
                   VALUES (?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(id) DO UPDATE SET
                     target_url=COALESCE(excluded.target_url, scan_runs.target_url),
                     status=COALESCE(excluded.status, scan_runs.status),
                     model=COALESCE(excluded.model, scan_runs.model),
                     total_cost=COALESCE(excluded.total_cost, scan_runs.total_cost),
                     total_input_tokens=COALESCE(excluded.total_input_tokens, scan_runs.total_input_tokens),
                     total_output_tokens=COALESCE(excluded.total_output_tokens, scan_runs.total_output_tokens),
                     workspace=COALESCE(excluded.workspace, scan_runs.workspace),
                     summary=COALESCE(excluded.summary, scan_runs.summary)""",
                (scan_id, target_url, status, model, total_cost,
                 input_tokens, output_tokens, created_at, workspace, summary))
        return cur.lastrowid

    def get_scan(self, scan_id):
        r = self.conn.execute("SELECT * FROM scan_runs WHERE id=?", (scan_id,)).fetchone()
        return dict(r) if r else None

    def list_scans(self, limit=50):
        rows = self.conn.execute(
            "SELECT * FROM scan_runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------- findings ----------
    def add_finding(self, scan_id, component, vuln_type, severity, location,
                    summary, steps=None, raw_json=None):
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO findings (scan_id, component, vuln_type, severity, location, summary, steps, raw_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id, component, vuln_type, severity, location, summary, steps, raw_json,
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        return cur.lastrowid

    def list_findings(self, scan_id=None, limit=200):
        if scan_id:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE scan_id=? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------- agents ----------
    def add_agent(self, scan_id, agent_name, attempt, status, duration_ms=None, cost_usd=None,
                  turns=None, input_tokens=None, output_tokens=None, model=None):
        with self.conn:
            cur = self.conn.execute(
                "INSERT INTO agents (scan_id, agent_name, attempt, status, duration_ms, cost_usd, turns, "
                "input_tokens, output_tokens, model, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (scan_id, agent_name, attempt, status, duration_ms, cost_usd, turns,
                 input_tokens, output_tokens, model, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
        return cur.lastrowid

    def list_agents(self, scan_id=None, limit=200):
        if scan_id:
            rows = self.conn.execute(
                "SELECT * FROM agents WHERE scan_id=? ORDER BY id DESC LIMIT ?", (scan_id, limit)).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM agents ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ---------- components ----------
    def upsert_component(self, name, version, category, file_path, scan_id):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.conn:
            cur = self.conn.execute(
                """INSERT INTO components (name, version, category, file_path, first_seen_scan, seen_count, last_seen)
                   VALUES (?,?,?,?,?,1,?)
                   ON CONFLICT(name, version) DO UPDATE SET
                     seen_count=components.seen_count+1, last_seen=excluded.last_seen,
                     first_seen_scan=COALESCE(components.first_seen_scan, excluded.first_seen_scan)""",
                (name, version, category, file_path, scan_id, now))
        return cur.lastrowid

    def list_components(self):
        rows = self.conn.execute(
            "SELECT * FROM components ORDER BY seen_count DESC, name").fetchall()
        return [dict(r) for r in rows]

    def get_component(self, name, version):
        r = self.conn.execute(
            "SELECT * FROM components WHERE name=? AND version=?", (name, version)).fetchone()
        return dict(r) if r else None

    # ---------- component_insights ----------
    def upsert_insight(self, component, version, summary, entry_points, data_flows, risk_tags, source_scan):
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with self.conn:
            self.conn.execute(
                """INSERT INTO component_insights (component, version, summary, entry_points, data_flows, risk_tags, source_scan, created_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(component, version) DO UPDATE SET
                     summary=excluded.summary, entry_points=excluded.entry_points,
                     data_flows=excluded.data_flows, risk_tags=excluded.risk_tags,
                     source_scan=excluded.source_scan""",
                (component, version, summary, entry_points, data_flows, risk_tags, source_scan, now))

    def get_insight(self, component, version=None):
        if version:
            r = self.conn.execute(
                "SELECT * FROM component_insights WHERE component=? AND version=?",
                (component, version)).fetchone()
        else:
            r = self.conn.execute(
                "SELECT * FROM component_insights WHERE component=? ORDER BY created_at DESC LIMIT 1",
                (component,)).fetchone()
        return dict(r) if r else None

    def list_insights(self):
        rows = self.conn.execute(
            "SELECT * FROM component_insights ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    # ---------- events ----------
    def add_event(self, scan_id, ts, agent, etype, detail, raw=None):
        with self.conn:
            self.conn.execute(
                "INSERT INTO events (scan_id, ts, agent, etype, detail, raw) VALUES (?,?,?,?,?,?)",
                (scan_id, ts, agent, etype, detail, raw))

    def list_events(self, scan_id, limit=300):
        rows = self.conn.execute(
            "SELECT ts, agent, etype, detail FROM events WHERE scan_id=? ORDER BY id DESC LIMIT ?",
            (scan_id, limit)).fetchall()
        return [dict(r) for r in reversed(rows)]

    # ---------- defender_events（防守方观测） ----------
    def add_defender_event(self, ts, source, layer, etype, process=None, path=None,
                           src_ip=None, method=None, url=None, status=None, tags=None, raw=None):
        with self.conn:
            self.conn.execute(
                "INSERT INTO defender_events (ts, source, layer, etype, process, path, src_ip, method, url, status, tags, raw, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (ts, source, layer, etype, process, path, src_ip, method, url, status,
                 json.dumps(tags, ensure_ascii=False) if tags else None, raw,
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))

    def add_defender_events_batch(self, events, source="target"):
        """批量入库防守方事件。events: list of dict。"""
        n = 0
        with self.conn:
            for ev in events:
                try:
                    self.conn.execute(
                        "INSERT INTO defender_events (ts, source, layer, etype, process, path, src_ip, method, url, status, tags, raw, created_at) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (ev.get("ts", time.time()), source, ev.get("layer", "unknown"),
                         ev.get("etype", ""), ev.get("process", ""), ev.get("path", ""),
                         ev.get("src_ip", ""), ev.get("method", ""), ev.get("url", ""),
                         ev.get("status", ""),
                         json.dumps(ev.get("tags", []), ensure_ascii=False),
                         json.dumps(ev, ensure_ascii=False),
                         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())))
                    n += 1
                except Exception:
                    continue
        return n

    def list_defender_events(self, limit=500, etype=None, since=None):
        sql = "SELECT * FROM defender_events WHERE 1=1"
        args = []
        if etype:
            sql += " AND etype=?"
            args.append(etype)
        if since:
            sql += " AND ts>=?"
            args.append(since)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = self.conn.execute(sql, args).fetchall()
        return [dict(r) for r in reversed(rows)]

    def defender_stats(self, hours=24):
        since = time.time() - hours * 3600
        s = {}
        s["total"] = self.conn.execute(
            "SELECT COUNT(*) c FROM defender_events WHERE ts>=?", (since,)).fetchone()["c"]
        s["by_etype"] = {}
        for r in self.conn.execute(
                "SELECT etype, COUNT(*) c FROM defender_events WHERE ts>=? GROUP BY etype", (since,)):
            s["by_etype"][r["etype"]] = r["c"]
        s["top_ip"] = [{"ip": r["src_ip"], "count": r["c"]} for r in self.conn.execute(
            "SELECT src_ip, COUNT(*) c FROM defender_events WHERE ts>=? AND src_ip!='' GROUP BY src_ip ORDER BY c DESC LIMIT 5",
            (since,))]
        s["top_process"] = [{"process": r["process"], "count": r["c"]} for r in self.conn.execute(
            "SELECT process, COUNT(*) c FROM defender_events WHERE ts>=? AND process!='' GROUP BY process ORDER BY c DESC LIMIT 10",
            (since,))]
        s["tagged"] = self.conn.execute(
            "SELECT COUNT(*) c FROM defender_events WHERE ts>=? AND tags!='[]' AND tags IS NOT NULL",
            (since,)).fetchone()["c"]
        return s

    # ---------- stats ----------
    def stats(self):
        s = {}
        s["scan_count"] = self.conn.execute("SELECT COUNT(*) c FROM scan_runs").fetchone()["c"]
        s["success_scans"] = self.conn.execute("SELECT COUNT(*) c FROM scan_runs WHERE status='success'").fetchone()["c"]
        s["component_count"] = self.conn.execute("SELECT COUNT(*) c FROM components").fetchone()["c"]
        s["finding_count"] = self.conn.execute("SELECT COUNT(*) c FROM findings").fetchone()["c"]
        s["total_cost"] = self.conn.execute("SELECT COALESCE(SUM(total_cost),0) s FROM scan_runs").fetchone()["s"]
        s["high_risk"] = self.conn.execute(
            "SELECT COUNT(*) c FROM findings WHERE severity IN ('critical','high')").fetchone()["c"]
        return s


# ---------- 组件指纹识别（从仓库文件识别技术栈） ----------
COMPONENT_PATTERNS = [
    # (类别, 文件名正则, 组件提取函数)
    ("js", "package.json", "package"),
    ("python", "requirements.txt", "requirements"),
    ("python", "pyproject.toml", "pyproject"),
    ("go", "go.mod", "gomod"),
    ("rust", "Cargo.toml", "cargo"),
]

def extract_package_json(content):
    """从 package.json 提取 dependencies 名称+版本。"""
    try:
        d = json.loads(content)
    except Exception:
        return []
    out = []
    for section in ("dependencies", "devDependencies"):
        for name, ver in (d.get(section) or {}).items():
            out.append((name, str(ver)))
    return out

def extract_requirements(content):
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" in line:
            continue
        parts = line.split("==")
        name = parts[0].strip().lower().replace("_", "-")
        ver = parts[1].strip() if len(parts) > 1 else "any"
        out.append((name, ver))
    return out

def extract_gomod(content):
    out = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith("require ") or "\t" in line:
            parts = line.split()
            if len(parts) >= 2 and "." in parts[0]:
                out.append((parts[0].split("/")[-1], parts[1]))
    return out

def extract_cargo(content):
    out = []
    for line in content.splitlines():
        line = line.strip()
        if line.startswith('"') and "=" in line and not line.startswith("["):
            parts = line.split("=")
            if len(parts) == 2:
                out.append((parts[0].strip().strip('"'), parts[1].strip().strip('"')))
    return out

def extract_pyproject(content):
    """PEP 621 风格：dependencies = ["fastapi>=0.100", "uvicorn[standard]>=0.24", ...]"""
    import re as _re
    out = []
    for line in content.splitlines():
        line = line.strip()
        if not (line.startswith('"') or line.startswith("'")):
            continue
        v = line.strip('"').strip("'").rstrip(",")
        if not v:
            continue
        # fastapi>=0.100.0 / uvicorn[standard]>=0.24.0 / python-jose[cryptography]>=3.3.0
        m = _re.match(r"^([\w.-]+)(?:\[[^\]]*\])?\s*(==|>=|<=|~=|!=|<|>)\s*([\d.]+)", v)
        if m:
            out.append((m.group(1), m.group(3)))
        elif " " not in v and "=" not in v:
            out.append((v, "any"))
    return out

def extract_pom(content):
    """Java Maven pom.xml：提取依赖 <artifactId>+<version> 对。"""
    out = []
    # 匹配 <dependency>...</dependency> 块内的 artifactId 与 version
    for dm in re.finditer(r"<dependency>(.*?)</dependency>", content, re.S):
        block = dm.group(1)
        am = re.search(r"<artifactId>\s*([\w.-]+)\s*</artifactId>", block)
        if not am:
            continue
        name = am.group(1)
        vm = re.search(r"<version>\s*([\w.-]+)\s*</version>", block)
        out.append((name, vm.group(1) if vm else "any"))
    # 兜底：裸 artifactId（无 version 时）
    if not out:
        for m in re.finditer(r"<artifactId>\s*([\w.-]+)\s*</artifactId>", content):
            out.append((m.group(1), "any"))
    return out


def extract_composer(content):
    """PHP composer.json。"""
    try:
        d = json.loads(content)
    except Exception:
        return []
    out = []
    for section in ("require", "require-dev"):
        for name, ver in (d.get(section) or {}).items():
            v = str(ver).lstrip("^~>=< ")
            out.append((name, v))
    return out


def extract_configure_ac(content):
    """C/C++ autotools：AC_INIT 定义项目名与版本，AM_INIT_AUTOMAKE。"""
    out = []
    m = re.search(r"AC_INIT\s*\(\s*\[?([\w.+-]+)\]?\s*,\s*\[?([\w.+-]+)\]?", content)
    if m:
        out.append((m.group(1), m.group(2)))
    return out


def extract_cmake(content):
    """C/C++ CMake：project() 定义项目名与版本。"""
    out = []
    for m in re.finditer(r"project\s*\(\s*([\w.-]+)\s*(?:VERSION\s+([\d.]+))?", content, re.I):
        out.append((m.group(1), m.group(2) or "any"))
    return out


def extract_gemfile(content):
    """Ruby Gemfile：gem 'name', 'version'。"""
    out = []
    for m in re.finditer(r"gem\s+['\"]([\w.-]+)['\"]\s*(?:,\s*['\"]([^'\"]+)['\"])?", content):
        out.append((m.group(1), m.group(2) or "any"))
    return out


def identify_components(files_content):
    """files_content: {相对路径: 内容文本}。返回组件列表。"""
    components = []
    for path, content in files_content.items():
        base = os.path.basename(path)
        try:
            if base == "package.json":
                for n, v in extract_package_json(content):
                    components.append({"name": n, "version": v, "category": "npm", "file_path": path})
            elif base == "requirements.txt":
                for n, v in extract_requirements(content):
                    components.append({"name": n, "version": v, "category": "python", "file_path": path})
            elif base == "go.mod":
                for n, v in extract_gomod(content):
                    components.append({"name": n, "version": v, "category": "go", "file_path": path})
            elif base == "Cargo.toml":
                for n, v in extract_cargo(content):
                    components.append({"name": n, "version": v, "category": "rust", "file_path": path})
            elif base == "pyproject.toml":
                for n, v in extract_pyproject(content):
                    components.append({"name": n, "version": v, "category": "python", "file_path": path})
            elif base == "pom.xml":
                for n, v in extract_pom(content):
                    components.append({"name": n, "version": v, "category": "java", "file_path": path})
            elif base == "composer.json":
                for n, v in extract_composer(content):
                    components.append({"name": n, "version": v, "category": "php", "file_path": path})
            elif base in ("configure.ac", "configure.in"):
                for n, v in extract_configure_ac(content):
                    components.append({"name": n, "version": v, "category": "c", "file_path": path})
            elif base in ("CMakeLists.txt", "cmake"):
                for n, v in extract_cmake(content):
                    components.append({"name": n, "version": v, "category": "c", "file_path": path})
            elif base == "Gemfile":
                for n, v in extract_gemfile(content):
                    components.append({"name": n, "version": v, "category": "ruby", "file_path": path})
        except Exception:
            pass
    return components


if __name__ == "__main__":
    import tempfile
    db = ShannonDB(os.path.join(tempfile.mkdtemp(), "test.db"))
    db.upsert_scan("test-1", target_url="http://t", status="running", model="deepseek:flash",
                   total_cost=0.1, input_tokens=100, output_tokens=10,
                   created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    db.add_finding("test-1", "demo", "SSRF", "high", "a.py:10", "test finding")
    db.add_agent("test-1", "recon", 1, "success", 1000, 0.05, 5, 100, 10, "deepseek:flash")
    db.upsert_component("fastapi", "0.100", "python", "requirements.txt", "test-1")
    db.upsert_insight("fastapi", "0.100", "FastAPI 默认无鉴权", "[]", "[]", '["auth"]', "test-1")
    print("stats:", db.stats())
    print("scans:", db.list_scans())
    print("components:", db.list_components())
    print("insight:", db.get_insight("fastapi", "0.100"))
    db.close()
    print("DB SELF-TEST PASSED")
