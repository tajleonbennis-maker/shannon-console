#!/usr/bin/env bash
# install_target_sensor.sh — 目标机一键安装安全监控（在目标机上执行）
#
# 安装内容：
#   1. auditd 系统行为审计（记录进程执行/文件访问）
#   2. tcpdump 网络抓包（记录攻击流量，按需开启）
#   3. target_sensor.py 采集器（systemd 常驻）
#   4. push_events.py 回传任务（把事件推到数据中枢）
#
# 用法（在目标机 43.159.146.42 上执行）:
#   sudo bash install_target_sensor.sh <数据中枢IP:端口> [--no-pcap] [--capture-port 8001]
set -euo pipefail

HUB="${1:?用法: sudo bash install_target_sensor.sh <中枢IP:端口> [--no-pcap]}"
HUB_IP="${HUB%%:*}"
HUB_PORT="${HUB##*:}"
NO_PCAP=""
CAPTURE_PORT="8001"
while [[ $# -gt 1 ]]; do
  case "$2" in
    --no-pcap) NO_PCAP="1"; shift ;;
    --capture-port) CAPTURE_PORT="$3"; shift 2 ;;
    *) shift ;;
  esac
done

echo "==> 1/4 安装基础工具"
apt-get update -qq
apt-get install -y -qq auditd audispd-plugins python3 curl tcpdump 2>/dev/null || yum install -y audit tcpdump python3 curl 2>/dev/null || true

echo "==> 2/4 配置 auditd 规则"
mkdir -p /etc/audit/rules.d
cat > /etc/audit/rules.d/shannon-attack.rules <<'EOF'
-w /etc/passwd -p wa -k shannon_attack
-w /etc/shadow -p wa -k shannon_attack
-w /etc/nginx/ -p wa -k shannon_attack
-w /var/www/ -p wa -k shannon_attack
-w /home/ -p wa -k shannon_attack
-w /tmp/ -p wa -k shannon_attack
-a always,exit -F arch=b64 -S execve -k shannon_exec
-a always,exit -F arch=b32 -S execve -k shannon_exec
EOF
service auditd restart 2>/dev/null || systemctl restart auditd 2>/dev/null || true

echo "==> 3/4 部署采集器"
SENSOR_DIR="/opt/shannon-sensor"
mkdir -p "$SENSOR_DIR"
cat > "$SENSOR_DIR/target_sensor.py" <<'PYEOF'
import argparse, glob, json, os, re, subprocess, time
DEFAULT_OUT = "/var/log/shannon-sensor/events.jsonl"
ATTACK_HINTS = {
    "sqli": [r"(\'|\")\s*(or|and)\s+(\'|\")\s*(\'|\")", r"union\s+select", r"sleep\s*\("],
    "xss": [r"<script", r"javascript:", r"onerror\s*=", r"alert\s*\("],
    "path_traversal": [r"\.\./", r"\.\.\\", r"etc/passwd", r"\.\.%2f"],
    "ssrf": [r"(http|https)://(127\.|10\.|192\.168\.|169\.254\.)", r"file://"],
    "auth_brute": [r"login", r"password", r"token"],
}
def tag_attack(text):
    low = (text or "").lower(); tags = []
    for name, pats in ATTACK_HINTS.items():
        for p in pats:
            if re.search(p, low): tags.append(name); break
    return tags
def read_audit(since_ts, max_events=200):
    events = []
    try:
        with open("/var/log/audit/audit.log", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError: return events
    for line in lines[-max_events:]:
        if not line.strip(): continue
        try:
            ts_m = re.search(r"audit\((\d+\.\d+):", line)
            if not ts_m: continue
            ts = float(ts_m.group(1))
            if ts <= since_ts: continue
            type_m = re.search(r"type=(\w+)", line)
            exe = re.search(r'exe="([^"]*)"', line)
            comm = re.search(r'comm="([^"]*)"', line)
            path = re.search(r'name="([^"]*)"', line)
            uid = re.search(r'uid=(\d+)', line)
            pid = re.search(r'pid=(\d+)', line)
            events.append({"ts": ts, "etype": type_m.group(1) if type_m else "AUDIT",
                "process": exe.group(1) if exe else (comm.group(1) if comm else ""),
                "path": path.group(1) if path else "", "uid": uid.group(1) if uid else "",
                "pid": pid.group(1) if pid else "", "tags": tag_attack(line)})
        except Exception: continue
    return events
def read_app(since_mark, max_events=200):
    events = []
    for pattern in ["/var/log/nginx/access.log", "/var/log/nginx/access.log.1",
                    "/var/log/app/access.log", "/opt/*/logs/access.log",
                    "/var/log/gunicorn/access.log"]:
        for path in glob.glob(pattern):
            try:
                size = os.path.getsize(path)
                if size <= since_mark.get(path, 0): continue
                since_mark[path] = size
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f.read().splitlines()[-max_events:]:
                        m = re.match(r'(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+[^"]*"\s+(\d+)', line)
                        if m:
                            ip, tm, method, url, status = m.groups()
                            events.append({"ts": time.time(), "etype": "HTTP", "src_ip": ip,
                                "method": method, "url": url[:300], "status": status,
                                "tags": tag_attack(f"{method} {url}")})
            except OSError: continue
            break
    return events
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--interval", type=int, default=5)
    p.add_argument("--out", default=DEFAULT_OUT)
    p.add_argument("--once", action="store_true")
    args = p.parse_args()
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    since_ts = time.time() - 300; since_mark = {}
    while True:
        try:
            evs = read_audit(since_ts) + read_app(since_mark)
            if evs:
                with open(args.out, "a", encoding="utf-8") as f:
                    for ev in evs: f.write(json.dumps(ev, ensure_ascii=False) + "\n")
                since_ts = max(e["ts"] for e in evs)
            if args.once: break
            time.sleep(args.interval)
        except KeyboardInterrupt: break
        except Exception as e:
            print(e)
            if args.once: break
            time.sleep(args.interval)
main()
PYEOF

echo "==> 4/4 部署 systemd 服务 + 回传任务"
mkdir -p /var/log/shannon-sensor
cat > /etc/systemd/system/shannon-sensor.service <<EOF
[Unit]
Description=Shannon target sensor
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SENSOR_DIR/target_sensor.py --interval 5
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 回传脚本（每 30s 把新事件推送到数据中枢）
cat > "$SENSOR_DIR/push_events.py" <<PYEOF
import json, os, time, urllib.request
OUT = "/var/log/shannon-sensor/events.jsonl"
HUB = "${HUB_IP}:${HUB_PORT}"
def push():
    try:
        with open(OUT, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if not lines: return
        events = [json.loads(l) for l in lines if l.strip()]
        data = json.dumps({"events": events, "source": "target-${HUB_IP}"}).encode()
        req = urllib.request.Request(f"http://{HUB}/api/defender-events",
            data=data, headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            if r.status == 200:
                # 成功后清空已推送事件（备份后截断）
                os.rename(OUT, OUT + ".bak")
                open(OUT, "w").close()
                print(f"[+] 推送 {len(events)} 条")
    except Exception as e:
        print(f"[!] {e}")
while True:
    push()
    time.sleep(30)
PYEOF

cat > /etc/systemd/system/shannon-push.service <<EOF
[Unit]
Description=Shannon sensor push
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SENSOR_DIR/push_events.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable shannon-sensor shannon-push
systemctl restart shannon-sensor shannon-push

# 按需启动抓包（后台，写 10MB 轮转）
if [[ -z "${NO_PCAP}" ]]; then
  mkdir -p /var/log/shannon-pcap
  nohup tcpdump -i any -s 0 -w /var/log/shannon-pcap/attack.pcap \
    -C 10 -W 20 "port ${CAPTURE_PORT}" > /dev/null 2>&1 &
  echo "    tcpdump 已启动: 抓取 port ${CAPTURE_PORT}，轮转 10MB x 20"
fi

echo ""
echo "==> 安装完成!"
echo "    事件文件: /var/log/shannon-sensor/events.jsonl"
echo "    回传目标: http://${HUB}/api/defender-events"
echo "    查看: journalctl -u shannon-sensor -f"
