#!/usr/bin/env python3
"""
pull_defender.py — 数据中枢主动拉取目标机防御事件（pull 模式）

背景：目标机(165.154.226.119)在公网，数据中枢(192.168.1.39)在内网，
     目标机连不到中枢，但中枢能连到目标机。所以中枢定时 SSH 拉取
     目标机传感器采集的事件文件，入库到 defender_events。

用法（在数据中枢 192.168.1.39 上，cron 或 systemd 定时跑）:
  python3 pull_defender.py [--interval 30]

依赖：sshpass（或配置 SSH 密钥）、scp
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

TARGET_HOST = "165.154.226.119"
TARGET_USER = "ubuntu"
TARGET_PASS = ""
TARGET_EVENTS = "/var/log/shannon-sensor/events.jsonl"
HUB_API = "http://127.0.0.1:8788/api/defender-events"
SOURCE = "165-target"


def load_creds():
    """从 ~/.ssh/shannon_hosts.json 读取目标机凭据（不硬编码）。"""
    global TARGET_USER, TARGET_PASS
    path = os.path.expanduser("~/.ssh/shannon_hosts.json")
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        t = cfg.get("target_machine", {})
        if t.get("host") == TARGET_HOST:
            TARGET_USER = t.get("user", TARGET_USER)
            TARGET_PASS = t.get("password", "")


def fetch_events():
    """scp 拉取目标机事件文件，返回事件列表 + 是否拉空。"""
    tmp = tempfile.mktemp(suffix=".jsonl")
    cmd = ["sshpass", "-p", TARGET_PASS, "scp", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=no",
           f"{TARGET_USER}@{TARGET_HOST}:{TARGET_EVENTS}", tmp]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return None, f"scp failed: {r.stderr[:200]}"
    if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
        os.remove(tmp)
        return [], ""
    events = []
    with open(tmp, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    os.remove(tmp)
    return events, ""


def push_to_hub(events):
    """把事件 POST 到中枢 API，成功则清空目标机文件。"""
    data = json.dumps({"events": events, "source": SOURCE}).encode()
    req = urllib.request.Request(HUB_API, data=data,
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            resp = json.loads(r.read().decode())
            return resp.get("ingested", 0)
    except Exception as e:
        return -1


def clear_target():
    """入库成功后清空目标机事件文件（截断保留备份）。"""
    cmd = ["sshpass", "-p", TARGET_PASS, "ssh", "-o", "ConnectTimeout=10",
           "-o", "StrictHostKeyChecking=no", TARGET_USER + "@" + TARGET_HOST,
           f"sudo bash -c 'if [ -s {TARGET_EVENTS} ]; then cp {TARGET_EVENTS} {TARGET_EVENTS}.bak; : > {TARGET_EVENTS}; fi'"]
    subprocess.run(cmd, capture_output=True, text=True)


def main():
    load_creds()
    if not TARGET_PASS:
        print("[ERR] 未找到目标机凭据 (~/.ssh/shannon_hosts.json)", file=sys.stderr)
        sys.exit(1)
    interval = int(sys.argv[sys.argv.index("--interval") + 1]) if "--interval" in sys.argv else 30
    print(f"[OK] pull_defender 启动: {TARGET_HOST} → {HUB_API} (间隔 {interval}s)")
    while True:
        try:
            events, err = fetch_events()
            if err:
                print(f"[!] {err}")
            elif events:
                n = push_to_hub(events)
                if n >= 0:
                    clear_target()
                    print(f"[+] 入库 {n}/{len(events)} 条防御事件")
                else:
                    print("[!] 入库失败，保留事件")
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[!] {e}")
        time.sleep(interval)


if __name__ == "__main__":
    main()
