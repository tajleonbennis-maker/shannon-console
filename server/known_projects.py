#!/usr/bin/env python3
"""
known_projects.py — 知名开源项目基线库

预置常见开源项目的基线知识：
  - 技术栈 / 构建系统指纹
  - 常见攻击面（模块、配置项、历史漏洞模式）
  - CVE 上下文

用途：
  - 新仓库指纹识别后，与基线比对 → 命中则直接展示历史结论
  - 提示后续扫描该项目的重点（跳过通用 pre-recon 重扫）

匹配规则：按组件名（大小写不敏感）与指纹文件内容匹配。
"""

KNOWN_PROJECTS = {
    "nginx": {
        "name": "nginx",
        "language": "C",
        "build": "configure / Makefile",
        "ecosystem": "c",
        "attack_surfaces": [
            "HTTP 请求解析（URI 规范化 / 路径穿越）",
            "配置指令注入（server/location 块）",
            "SSI / sub_filter 模块注入",
            "Lua 模块（ngx_lua）执行面",
            "TLS/HTTP2 解析器",
        ],
        "cve_context": [
            "CVE-2021-23017: DNS 解析器堆溢出（1.21.0 之前）",
            "CVE-2017-7529: 整数溢出信息泄露（range 过滤器）",
            "CVE-2019-9511/9513: HTTP/2 资源耗尽",
        ],
        "known_config_risks": [
            "alias 拼接路径穿越（配置错误）",
            "proxy_pass 未加尾斜杠导致路径歧义",
            "client_body_temp 目录权限",
            "default server 未配置导致意外暴露",
        ],
        "summary": "Nginx 高性能 Web 服务器/反向代理，C 语言，配置驱动。审计重点：URI 解析、alias/root 路径穿越、SSI/Lua 注入、历史 DNS/HTTP2 漏洞版本匹配。",
    },
    "redis": {
        "name": "redis",
        "language": "C",
        "build": "Makefile",
        "ecosystem": "c",
        "attack_surfaces": [
            "协议解析（RESP）",
            "未授权访问（bind/requirepass 配置）",
            "命令注入（EVAL/SCRIPT LOAD）",
            "Lua 沙箱逃逸",
            "复制/持久化机制（RDB/AOF）",
        ],
        "cve_context": [
            "CVE-2022-0543: Lua 沙箱逃逸 RCE",
            "CVE-2021-32761: 整数溢出（BITFIELD）",
            "CVE-2016-8339: 越界写",
        ],
        "known_config_risks": [
            "未设密码绑定 0.0.0.0",
            "危险命令未 rename",
            "protected-mode 关闭",
        ],
        "summary": "Redis 内存数据库，C 语言。审计重点：未授权访问、Lua 沙箱逃逸、RESP 协议解析、命令执行面。",
    },
    "openssl": {
        "name": "openssl",
        "language": "C",
        "build": "Configure / Makefile",
        "ecosystem": "c",
        "attack_surfaces": [
            "TLS 握手解析",
            "ASN.1/DER 解析",
            "证书链验证逻辑",
            "密码学实现（常量时间、侧信道）",
        ],
        "cve_context": [
            "CVE-2014-0160: Heartbleed 心脏出血",
            "CVE-2022-3602/3786: X.509 邮箱地址越界读",
            "CVE-2016-2107: Lucky 13 padding oracle",
        ],
        "known_config_risks": [],
        "summary": "OpenSSL TLS/密码学库，C 语言。审计重点：协议解析、ASN.1、证书验证、已知版本漏洞匹配。",
    },
    "fastapi": {
        "name": "fastapi",
        "language": "Python",
        "build": "pyproject.toml / pip",
        "ecosystem": "python",
        "attack_surfaces": [
            "路由/依赖注入（Depends）",
            "OpenAPI 文档暴露",
            "Pydantic 校验绕过",
            "文件上传/响应模型",
        ],
        "cve_context": [
            "CVE-2024-24762: python-multipart DoS",
        ],
        "known_config_risks": [
            "docs/redoc 未关闭暴露 API 结构",
            "CORS 配置过宽",
            "路径参数类型校验缺失",
        ],
        "summary": "FastAPI 高性能 Python Web 框架。审计重点：依赖注入鉴权、OpenAPI 暴露面、Pydantic 校验、CORS。",
    },
    "spring": {
        "name": "spring",
        "language": "Java",
        "build": "Maven/Gradle",
        "ecosystem": "java",
        "attack_surfaces": [
            "Spring MVC 路径匹配",
            "SpEL 表达式注入",
            "Actuator 端点暴露",
            "反序列化（XStream/Jackson）",
        ],
        "cve_context": [
            "CVE-2022-22965: Spring4Shell RCE",
            "CVE-2022-22947: Spring Cloud Gateway SpEL RCE",
            "CVE-2016-1000027: HttpInvoker 反序列化",
        ],
        "known_config_risks": [
            "actuator 未鉴权暴露",
            "SpEL 用户输入拼接",
        ],
        "summary": "Spring 系 Java 框架。审计重点：SpEL 注入、Actuator 暴露、路径匹配绕过、反序列化链。",
    },
    "nextjs": {
        "name": "next.js",
        "language": "TypeScript/JavaScript",
        "build": "package.json",
        "ecosystem": "npm",
        "attack_surfaces": [
            "SSR/中间件（middleware/proxy）",
            "服务端组件数据获取",
            "Image Optimization 端点",
            "API Routes 鉴权",
        ],
        "cve_context": [
            "CVE-2025-29927: middleware 鉴权绕过",
            "CVE-2024-34351: SSRF (image optimization)",
        ],
        "known_config_risks": [
            "next.config images 域名白名单过宽",
            "middleware 绕过（CVE-2025-29927 模式）",
            "客户端 secret 泄露",
        ],
        "summary": "Next.js React 全栈框架。审计重点：middleware 鉴权绕过、Image Optimization SSRF、服务端数据流。",
    },
}


def match_known_project(components):
    """根据识别出的组件名匹配基线库。返回命中列表 [{name, info}]。"""
    hits = []
    seen = set()
    for c in components:
        name = (c.get("name") or "").strip().lower()
        if not name:
            continue
        for known, info in KNOWN_PROJECTS.items():
            key = known.lower()
            if key == name or key in name or name in key:
                if known not in seen:
                    seen.add(known)
                    hits.append({"name": known, "info": info})
    return hits


if __name__ == "__main__":
    # 自测：nginx 指纹 → 命中
    test = [{"name": "nginx", "version": "1.24.0", "category": "c"}]
    hits = match_known_project(test)
    for h in hits:
        print(f"命中: {h['name']}")
        print(f"  语言: {h['info']['language']} | 构建: {h['info']['build']}")
        print(f"  摘要: {h['info']['summary'][:80]}...")
    print("KNOWN PROJECTS SELF-TEST PASSED")
