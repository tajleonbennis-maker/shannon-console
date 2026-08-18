#!/usr/bin/env python3
"""SurferCloud API 客户端（签名算法官方验证版）
签名算法：参数按 key 升序 → 无分隔符拼接 key+value → 末尾拼 PrivateKey → SHA1(hex)
"""
import hashlib
import urllib.parse
import urllib.request
import json
import sys

API_BASE = "https://api.surfercloud.com"


def sign(params: dict, private_key: str) -> str:
    sorted_keys = sorted(params.keys())
    s = "".join(f"{k}{params[k]}" for k in sorted_keys) + private_key
    return hashlib.sha1(s.encode()).hexdigest()


def api_call(params: dict, private_key: str):
    params["Signature"] = sign(params, private_key)
    url = API_BASE + "/?" + urllib.parse.urlencode(params)
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return {"RetCode": e.code, "Message": e.read().decode()[:300]}
    except Exception as e:
        return {"RetCode": -1, "Message": str(e)}


def verify_official_example():
    """官方示例验证：应得到 4201919d267504385deb93af19e0197870fed36b"""
    params = {"Action": "DescribeUHostInstance", "Limit": 10,
              "PublicKey": "someone@example.com1296235120854146120", "Region": "cn-bj2"}
    pk = "46f09bb9fab4f12dfc160dae12273d5332b5debe"
    sig = sign(params, pk)
    print(f"[verify] signature = {sig}")
    print(f"[verify] expect    = 4201919d267504385deb93af19e0197870fed36b")
    return sig == "4201919d267504385deb93af19e0197870fed36b"


if __name__ == "__main__":
    ok = verify_official_example()
    print("[verify]", "PASS" if ok else "FAIL")
    if not ok:
        sys.exit(1)
