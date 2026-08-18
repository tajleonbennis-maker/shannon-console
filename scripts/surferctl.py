#!/usr/bin/env python3
"""
surferctl.py — SurferCloud 临时目标机生命周期管理

命令：
  list                              列出所有实例
  create   --region hk --zone hk-02 --name deep-tutor --image uimage-xxx
           [--cpu 4 --mem 8192 --password xxx] [--charge Dynamic]
  start    <UHostId>                 开机
  stop     <UHostId>                 停机（按小时计费停机不计费）
  reset    <UHostId> [--password]    重装系统（用完重置，回到初始镜像）
  destroy  <UHostId>                 销毁实例
  info     <UHostId>                 实例详情（含 IP）

凭据：~/.surfercloud/config.json
用法示例：
  python3 surferctl.py create --region hk --zone hk-02 --name tgt --image uimage-1qehsqbotgjm
"""
import argparse
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from surfercloud_api import api_call

CONFIG = json.load(open(os.path.expanduser("~/.surfercloud/config.json")))
PUB = CONFIG["public_key"]
PRIV = CONFIG["private_key"]
DEFAULT_REGION = "hk"
DEFAULT_ZONE = "hk-02"
DEFAULT_IMAGE = "uimage-1qehsqbotgjm"  # Ubuntu 20.04 (hk)
DEFAULT_PASSWORD = "Sc@nTgt2026!tmp"


def call(action, **extra):
    params = {"Action": action, "PublicKey": PUB, **extra}
    r = api_call(params, PRIV)
    if r.get("RetCode") != 0:
        print(f"[ERR] {action}: {r.get('Message', r)}", file=sys.stderr)
        sys.exit(1)
    return r


def list_instances(args):
    r = call("DescribeUHostInstance", Region=args.region)
    hosts = r.get("UHostSet", [])
    if not hosts:
        print("(无实例)")
        return
    for u in hosts:
        ip = ""
        for eip in (u.get("IPSet") or []):
            if isinstance(eip, dict) and eip.get("EIP"):
                ip = eip["EIP"].get("IP", "")
        print(f"{u.get('UHostId')} | {u.get('Name','?')} | {u.get('State')} | {ip} | CPU:{u.get('CPU')} Mem:{u.get('MemoryMB')}MB")


def create_instance(args):
    # 密码 base64（API 要求）
    pw = base64.b64encode(args.password.encode()).decode()
    params = {
        "Region": args.region, "Zone": args.zone,
        "UHostType": "O", "CPU": args.cpu, "MemoryMB": args.mem,
        "ImageId": args.image, "Password": pw, "LoginMode": "Password",
        "Name": args.name, "ChargeType": args.charge, "Quantity": 1,
        "StorageType": "UDisk",
        "Disks.0.Type": "CLOUD_SSD", "Disks.0.Size": args.disk, "Disks.0.IsBoot": "True",
        "NetworkInterface.0.EIP.OperatorName": "International",
        "NetworkInterface.0.EIP.PayMode": "Bandwidth",
        "NetworkInterface.0.EIP.Bandwidth": 2,
    }
    r = call("CreateUHostInstance", **params)
    ids = r.get("UHostIds", [])
    print(f"[OK] 创建请求已提交: {ids}")
    print(f"  等待实例就绪（约 60-120s）...")
    for _ in range(12):
        time.sleep(10)
        d = call("DescribeUHostInstance", Region=args.region)
        for u in d.get("UHostSet", []):
            if u.get("UHostId") in ids and u.get("State") in ("Running", "Start"):
                ip = ""
                for eip in (u.get("IPSet") or []):
                    if isinstance(eip, dict) and eip.get("EIP"):
                        ip = eip["EIP"].get("IP", "")
                print(f"[OK] 实例 {u.get('UHostId')} 已就绪: {u.get('Name')} @ {ip}")
                print(f"    SSH: ssh ubuntu@{ip}  (密码: {args.password})")
                return
    print("[WARN] 等待超时，请用 info 命令查询状态")


def start_instance(args):
    r = call("StartUHostInstance", Region=args.region, UHostId=args.id)
    print(f"[OK] 开机命令已下发: {args.id}")


def stop_instance(args):
    r = call("StopUHostInstance", Region=args.region, UHostId=args.id)
    print(f"[OK] 停机命令已下发: {args.id}")


def reset_instance(args):
    """重装系统 = 用完重置。镜像可换（默认原镜像）。"""
    pw = base64.b64encode(args.password.encode()).decode()
    r = call("ReinstallUHostInstance", Region=args.region, UHostId=args.id,
             Password=pw, LoginMode="Password", ImageId=args.image)
    print(f"[OK] 重装系统已触发: {args.id}（完成后回到初始镜像，目标环境被清空）")


def destroy_instance(args):
    r = call("TerminateUHostInstance", Region=args.region, UHostId=args.id)
    print(f"[OK] 销毁已触发: {args.id}")


def instance_info(args):
    d = call("DescribeUHostInstance", Region=args.region, UHostIds=[args.id])
    for u in d.get("UHostSet", []):
        print(json.dumps({k: u.get(k) for k in
              ("UHostId", "Name", "State", "CPU", "MemoryMB", "ImageId", "CreateTime", "UHostType")},
              ensure_ascii=False, indent=2))
        for eip in (u.get("IPSet") or []):
            if isinstance(eip, dict) and eip.get("EIP"):
                print("EIP:", eip["EIP"].get("IP", ""))
        if u.get("NetworkState"):
            print("NetworkState:", u["NetworkState"])


def main():
    p = argparse.ArgumentParser(description="SurferCloud 临时目标机管理")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, help_ in [("list", "列出实例"), ("create", "创建"), ("start", "开机"),
                        ("stop", "停机"), ("reset", "重装系统"), ("destroy", "销毁"), ("info", "详情")]:
        s = sub.add_parser(name, help=help_)
        s.add_argument("--region", default=DEFAULT_REGION)
        s.add_argument("--zone", default=DEFAULT_ZONE)
        s.add_argument("--id", default=None)
        s.add_argument("--name", default="shannon-target")
        s.add_argument("--image", default=DEFAULT_IMAGE)
        s.add_argument("--cpu", type=int, default=4)
        s.add_argument("--mem", type=int, default=8192)
        s.add_argument("--disk", type=int, default=40)
        s.add_argument("--password", default=DEFAULT_PASSWORD)
        s.add_argument("--charge", default="Dynamic")
    args = p.parse_args()
    fn = "list_instances" if args.cmd == "list" else f"{args.cmd}_instance"
    globals()[fn](args)


if __name__ == "__main__":
    main()
