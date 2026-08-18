#!/usr/bin/env bash
# deploy.sh — 一键部署 Shannon Console 到内网服务器（192.168.1.39 或任意目标）
#
# 用法:
#   ./deploy.sh <user@host> [--db /path/to/shannon.db] [--token 可选访问令牌] [--port 8788]
#
# 说明:
#   - 将 server/ + web/ 同步到目标机 /opt/shannon-console/
#   - 注册 systemd 服务 shannon-console（开机自启）
#   - 数据文件（shannon.db）默认放 /opt/shannon-console/data/，可 --db 指定
#   - 目标机需 Python 3.8+（零第三方依赖）
set -euo pipefail

HOST="${1:?用法: ./deploy.sh <user@host> [--db PATH] [--token TOKEN] [--port PORT]}"
shift
DB_PATH="/opt/shannon-console/data/shannon.db"
TOKEN=""
PORT="8788"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --db) DB_PATH="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo "==> 源目录: $SRC_DIR"
echo "==> 目标: $HOST  (db=$DB_PATH port=$PORT)"

echo "==> 同步代码到 $HOST:/opt/shannon-console/"
ssh "$HOST" "sudo mkdir -p /opt/shannon-console/server /opt/shannon-console/web /opt/shannon-console/data && sudo chown -R \$(whoami) /opt/shannon-console"
scp "$SRC_DIR/server/shannon_db.py" "$SRC_DIR/server/shannon_ingest.py" "$SRC_DIR/server/shannon_server.py" "$HOST":/opt/shannon-console/server/
scp "$SRC_DIR/web/index.html" "$HOST":/opt/shannon-console/web/

echo "==> 写入 systemd 服务"
ssh "$HOST" "cat > /tmp/shannon-console.service <<'EOF'
[Unit]
Description=Shannon Console - 攻击面情报平台
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/shannon-console/server/shannon_server.py --host 0.0.0.0 --port ${PORT} --db ${DB_PATH} ${TOKEN:+--token ${TOKEN}}
WorkingDirectory=/opt/shannon-console
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
sudo mv /tmp/shannon-console.service /etc/systemd/system/shannon-console.service
sudo systemctl daemon-reload
sudo systemctl enable shannon-console
sudo systemctl restart shannon-console
sleep 2
sudo systemctl status shannon-console --no-pager | head -8"

echo ""
echo "==> 完成! 访问: http://$HOST:${PORT}/"
echo "    数据文件: $DB_PATH"
echo "    手动操作: sudo systemctl {start|stop|restart|status} shannon-console"
