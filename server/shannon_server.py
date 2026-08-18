#!/usr/bin/env python3
"""
shannon_server.py — Shannon Console 后端 API + 实时监控

提供：
  GET  /                   前端页面
  GET  /api/stats          统计概览
  GET  /api/scans          扫描列表
  GET  /api/scans/<id>     扫描详情（含 agents/findings/events）
  GET  /api/components     组件库
  GET  /api/insights       组件分析结论
  GET  /api/findings       漏洞发现（可按 scan 过滤）
  GET  /api/events?scan=   事件流
  POST /api/ingest         触发入库（body: {workspace, repo_dir, scan_id?}）
  GET  /api/live           实时监控快照（SSE /stream）

纯 Python 标准库，零依赖。
"""
import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from shannon_db import ShannonDB
from shannon_ingest import ingest

DB_PATH = "shannon.db"
AUTH_TOKEN = None
INGEST_LOCK = threading.Lock()


def api_ok(data):
    body = json.dumps(data, ensure_ascii=False).encode()
    return 200, {"Content-Type": "application/json; charset=utf-8"}, body


def api_err(code, msg):
    body = json.dumps({"error": msg}, ensure_ascii=False).encode()
    return code, {"Content-Type": "application/json; charset=utf-8"}, body


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def authorized(self, parsed):
        if not AUTH_TOKEN:
            return True
        if self.headers.get("Authorization") == f"Bearer {AUTH_TOKEN}":
            return True
        qs = parse_qs(parsed.query)
        return qs.get("token", [None])[0] == AUTH_TOKEN

    def _send(self, code, headers, body):
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if not self.authorized(parsed):
            self._send(*api_err(401, "unauthorized"))
            return

        db = ShannonDB(DB_PATH)
        try:
            if parsed.path in ("/", "/index.html"):
                page = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "index.html")
                with open(page, "rb") as f:
                    self._send(200, {"Content-Type": "text/html; charset=utf-8"}, f.read())
                return

            if parsed.path == "/api/stats":
                self._send(*api_ok(db.stats()))
            elif parsed.path == "/api/scans":
                self._send(*api_ok({"scans": db.list_scans(limit=100)}))
            elif parsed.path.startswith("/api/scans/"):
                sid = parsed.path[len("/api/scans/"):].strip("/")
                scan = db.get_scan(sid)
                if not scan:
                    self._send(*api_err(404, "scan not found"))
                    return
                scan["agents"] = db.list_agents(sid)
                scan["findings"] = db.list_findings(sid)
                scan["events"] = db.list_events(sid, limit=300)
                self._send(*api_ok(scan))
            elif parsed.path == "/api/components":
                self._send(*api_ok({"components": db.list_components()}))
            elif parsed.path == "/api/insights":
                self._send(*api_ok({"insights": db.list_insights()}))
            elif parsed.path == "/api/known-projects":
                try:
                    from known_projects import KNOWN_PROJECTS
                    self._send(*api_ok({"projects": KNOWN_PROJECTS}))
                except ImportError:
                    self._send(*api_err(500, "known_projects not found"))
            elif parsed.path == "/api/findings":
                qs = parse_qs(parsed.query)
                scan_id = qs.get("scan", [None])[0]
                self._send(*api_ok({"findings": db.list_findings(scan_id, limit=500)}))
            elif parsed.path == "/api/events":
                qs = parse_qs(parsed.query)
                scan_id = qs.get("scan", [None])[0]
                if not scan_id:
                    self._send(*api_err(400, "need ?scan="))
                    return
                self._send(*api_ok({"events": db.list_events(scan_id, limit=500)}))
            elif parsed.path == "/api/health":
                self._send(*api_ok({"ok": True, "time": time.strftime("%H:%M:%S")}))
            else:
                self._send(*api_err(404, "not found"))
        finally:
            db.close()

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self.authorized(parsed):
            self._send(*api_err(401, "unauthorized"))
            return
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode())
        except Exception:
            body = {}
        if parsed.path == "/api/ingest":
            with INGEST_LOCK:
                try:
                    result = ingest(body.get("workspace", ""), DB_PATH,
                                    repo_dir=body.get("repo_dir"),
                                    scan_id_override=body.get("scan_id"))
                    self._send(*api_ok(result))
                except Exception as e:
                    self._send(*api_err(500, f"ingest failed: {e}"))
        else:
            self._send(*api_err(404, "not found"))


def main():
    global DB_PATH, AUTH_TOKEN
    parser = argparse.ArgumentParser(description="Shannon Console 后端")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8788)
    parser.add_argument("--db", default="shannon.db")
    parser.add_argument("--token", default=None, help="访问令牌（Authorization: Bearer 或 ?token=）")
    args = parser.parse_args()
    DB_PATH = args.db
    AUTH_TOKEN = args.token
    ShannonDB(DB_PATH)  # 确保 schema 就绪
    auth = f"token 已启用" if AUTH_TOKEN else "无鉴权（仅本机）"
    print(f"[OK] Shannon Console: http://{args.host}:{args.port} [{auth}]")
    print(f"     DB: {args.db}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
