#!/usr/bin/env python3
"""
target_sensor.py — 目标机安全监控采集器（部署在被攻击方）

作用：采集 shannon 攻击行为的三层观测数据，推送到数据中枢入库。

三层监控：
  1. 系统行为审计：读取 auditd 日志 /var/log/audit/audit.log
     记录进程执行(EXECVE)、文件访问(PATH)、系统调用(SYSCALL)
  2. 应用访问日志：读取目标应用访问日志（FastAPI/nginx），
     记录 shannon 打过的每个请求（IP/方法/路径/状态码）
  3. 网络抓包：tcpdump 抓取攻击流量（按需开启，数据量大）

输出：JSON 行追加到 /var/log/shannon-sensor/events.jsonl
     由 push_events.py 定期推送到数据中枢 /api/events/ingest

用法：
  python3 target_sensor.py [--interval 5] [--out /var/log/shannon-sensor/events.jsonl]
"""
import argparse
import glob
import json
import os
import re
import subprocess
import time

DEFAULT_OUT = "/var/log/shannon-sensor/events.jsonl"

# 常见攻击特征（用于给事件打标签）
ATTACK_HINTS = {
    "sqli": [r"(\'|\")\s*(or|and)\s+(\'|\")\s*(\'|\")", r"union\s+select", r"sleep\s*\("],
    "xss": [r"<script", r"javascript:", r"onerror\s*=", r"alert\s*\("],
    "path_traversal": [r"\.\./", r"\.\.\\", r"etc/passwd", r"\.\.%2f"],
    "ssrf": [r"(http|https)://(127\.|10\.|192\.168\.|169\.254\.)", r"file://"],
    "auth_brute": [r"login", r"password", r"token"],
    "scanner": [r"(nmap|nikto|sqlmap|gobuster|ffuf|dirb|wpscan)"],
}


def tag_attack(text):
    """给日志文本打攻击类型标签。"""
    low = (text or "").lower()
    tags = []
    for name, patterns in ATTACK_HINTS.items():
        for p in patterns:
            if re.search(p, low):
                tags.append(name)
                break
    return tags


def read_audit_log(since_ts, max_events=200):
    """读取 auditd 日志，返回新增事件。需要 root/sudo 读 /var/log/audit/audit.log。"""
    events = []
    try:
        with open("/var/log/audit/audit.log", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return events
    for line in lines[-max_events:]:
        if not line.strip():
            continue
        try:
            # audit 行格式: type=EXECVE msg=audit(1234567.890:123): ...
            ts_m = re.search(r"audit\((\d+\.\d+):", line)
            if not ts_m:
                continue
            ts = float(ts_m.group(1))
            if ts <= since_ts:
                continue
            type_m = re.search(r"type=(\w+)", line)
            # 提取关键字段
            exe = re.search(r'exe="([^"]*)"', line)
            comm = re.search(r'comm="([^"]*)"', line)
            path = re.search(r'name="([^"]*)"', line)
            uid = re.search(r'uid=(\d+)', line)
            pid = re.search(r'pid=(\d+)', line)
            events.append({
                "ts": ts,
                "etype": type_m.group(1) if type_m else "AUDIT",
                "process": exe.group(1) if exe else (comm.group(1) if comm else ""),
                "path": path.group(1) if path else "",
                "uid": uid.group(1) if uid else "",
                "pid": pid.group(1) if pid else "",
                "tags": tag_attack(line),
            })
        except Exception:
            continue
    return events


def read_app_log(since_mark, max_events=200):
    """读取目标应用访问日志（FastAPI/nginx/gunicorn 常见位置）。"""
    events = []
    candidates = [
        "/var/log/nginx/access.log",
        "/var/log/nginx/access.log.1",
        "/var/log/app/access.log",
        "/home/*/app/logs/access.log",
        "/opt/*/logs/access.log",
        "/var/log/gunicorn/access.log",
    ]
    for pattern in candidates:
        for path in glob.glob(pattern):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            if not content:
                continue
            # 取文件末尾新增部分（简单按大小标记）
            size = os.path.getsize(path)
            if size <= since_mark.get(path, 0):
                continue
            since_mark[path] = size
            for line in content.splitlines()[-max_events:]:
                # nginx 格式: IP - - [time] "METHOD /path HTTP/1.1" status size
                m = re.match(r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+[^"]*"\s+(\d+)', line)
                if m:
                    ip, tm, method, url, status = m.groups()
                    events.append({
                        "ts": time.time(),
                        "etype": "HTTP",
                        "src_ip": ip,
                        "method": method,
                        "url": url[:300],
                        "status": status,
                        "tags": tag_attack(f"{method} {url}"),
                    })
            break
    return events


def main():
    parser = argparse.ArgumentParser(description="目标机安全监控采集器")
    parser.add_argument("--interval", type=int, default=5, help="采集间隔秒")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--once", action="store_true", help="只跑一次")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    since_ts = time.time() - 300  # 首次回看 5 分钟
    since_mark = {}
    print(f"[OK] target_sensor 启动: {args.out} (间隔 {args.interval}s)")

    while True:
        try:
            events = []
            events += read_audit_log(since_ts)
            events += read_app_log(since_mark)
            if events:
                with open(args.out, "a", encoding="utf-8") as f:
                    for ev in events:
                        f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                print(f"[+] 采集 {len(events)} 条事件")
                if events:
                    since_ts = max(ev["ts"] for ev in events)
            if args.once:
                break
            time.sleep(args.interval)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] {e}")
            if args.once:
                break
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
