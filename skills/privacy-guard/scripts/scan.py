#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""隐私/敏感数据检测引擎。

设计目标：在「项目工作区」与「git 全量历史」中找出硬编码的敏感数据，
分 5 大类、按严重级输出**脱敏**报告，确定性强、误报可控、Claude 与 Codex 都能直接跑。

效率策略（rg + Python，谁高效用谁）：
- 工作区扫描：若有 ripgrep(rg)，先用一次 rg 把「可能命中任意规则」的候选文件筛出来
  （union 预筛正则，召回优先、允许过宽），再用 Python 精确分类 + 校验（熵值/Luhn/身份证/白名单）。
  rg 不可用时退化为纯 Python 遍历，结果一致只是更慢。
- 历史扫描：rg 够不到 git 对象，改为枚举全量 reachable blob 并按 blob 去重，
  每份内容只扫一次，再用 Python 规则分类。

安全自律：报告里**绝不**落明文密钥——所有命中片段一律打码后展示。
本脚本只检测、只报告，绝不改写工作区或 git 历史。
"""

import argparse
import fnmatch
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import OrderedDict

# ── 扫描时跳过的噪声目录（构建产物/依赖/虚拟环境，几乎不含手写敏感数据，且拖慢扫描）──
NOISE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    "target", ".gradle", ".idea", ".vscode", ".mypy_cache", ".pytest_cache",
    "vendor", ".next", "out", "bin", "obj", ".terraform", "coverage",
}
# 单文件体积上限（字节）：超大文件多为数据/产物，跳过以保扫描速度
MAX_FILE_BYTES = 5 * 1024 * 1024

# 占位/示例值：命中这些一律视为非真实泄露，抑制误报
PLACEHOLDER_RE = re.compile(
    r"(?i)(your[_-]?|my[_-]?|example|sample|dummy|placeholder|changeme|change[_-]?me|"
    r"xxxx+|<[^>]*>|\.\.\.+|test[_-]?key|fake|todo|replace[_-]?me|insert[_-]?|"
    r"AKIAIOSFODNN7EXAMPLE|wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)"
)
# 本地用户名路径里可放过的通用名（CI/容器/通用占位，非真人姓名）
GENERIC_USERNAMES = {
    "runner", "user", "root", "administrator", "admin", "home", "ubuntu",
    "vagrant", "ec2-user", "build", "ci", "jenkins", "node", "app", "www-data",
}


def shannon_entropy(s):
    """计算字符串的香农熵（bits/char），用于判定「看起来随机」的高强度密钥。"""
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def luhn_valid(num):
    """Luhn 校验：用于把 13-19 位数字里真正像银行卡/信用卡的挑出来，压低误报。"""
    digits = [int(d) for d in num if d.isdigit()]
    if len(digits) < 13:
        return False
    total, alt = 0, False
    for d in reversed(digits):
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _is_datetime14(num):
    """14 位 yyyymmddhhmmss 时间戳判定。
    Go 伪版本号（v0.0.0-20240121214520-…）、go.sum 哈希行、日志时间戳都是这种 14 位串，
    会以约 1/10 的概率偶然通过 Luhn 校验而被 bank-card 误判，故在校验中排除。"""
    if len(num) != 14:
        return False
    y, mo, d = int(num[0:4]), int(num[4:6]), int(num[6:8])
    h, mi, s = int(num[8:10]), int(num[10:12]), int(num[12:14])
    return (1970 <= y <= 2099 and 1 <= mo <= 12 and 1 <= d <= 31
            and h <= 23 and mi <= 59 and s <= 59)


def _in_hex_run(m):
    """命中的数字串只是一段长十六进制串（sha256 / sha1 / md5 校验和、哈希）的一部分。
    如 Cargo.lock 的 checksum = "9330f8b2ff13f345…"，其中的连续数字子串会偶然通过 Luhn / 身份证校验。
    要求所在的连续 [0-9a-f] 串至少 20 位，避免把 `13812345678ext.123` 这类紧跟字母的真号码误放。"""
    s, a, b = m.string, m.start(), m.end()
    while a > 0 and s[a - 1] in "0123456789abcdefABCDEF":
        a -= 1
    while b < len(s) and s[b] in "0123456789abcdefABCDEF":
        b += 1
    if b - a >= 20 and b - a > m.end() - m.start():
        return True
    # UUID 每组最长只有 12 位，单看连续十六进制串不够长，按 UUID 整体形状判断
    # 只在命中附近 36 字符窗口内找，避免长行里每个候选都全行搜索
    lo = max(0, m.start() - 36)
    win = s[lo:m.end() + 36]
    return any(lo + u.start() <= m.start() and m.end() <= lo + u.end() for u in _UUID_RE.finditer(win))


_UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def bank_card_valid(m):
    """银行卡校验：Luhn 通过，且排除两类高频「数字串」误报 ——
    ① 浮点小数尾数：命中串紧邻前缀为 `<数字>.`（如 Prometheus 指标 20.00242334472774 的小数部分）；
    ② 14 位 yyyymmddhhmmss 时间戳（Go 伪版本号 / go.sum 哈希行 / 日志时间戳）。
    Luhn 无法区分这些串与真实卡号（任意 14 位串约 1/10 撞中），故以语义守卫补足精度。"""
    num = m.group(0)
    if not luhn_valid(num):
        return False
    if _in_hex_run(m):
        return False
    if _is_datetime14(num):
        return False
    if re.search(r"\d\.$", m.string[:m.start()]):
        return False
    return True


# 反向域名式包名的首段（top.wcpe.xxx / com.example.xxx），真实主机名不会以这些顶级域开头
_REVERSE_DOMAIN_HEADS = {"com", "org", "net", "io", "top", "cn", "dev", "me", "edu", "gov", "co", "xyz",
                         "app", "info", "biz", "uk", "de", "jp", "fr", "ru", "us", "eu", "tech", "site"}


def internal_host_valid(m):
    """内网主机名校验：排除 Java/Kotlin 包名与 import 里恰好含 .internal / .local 段的点分路径。
    ① 命中正是 package / import 关键字后的包名本身，且后面不接 `/` 或 `:`（接了就是 Go 模块路径 / URL 里的真主机名）；② 命中后还接着 `.标识符`（internal 只是中间段，不是顶级域）且首段是常见顶级域
    （反向域名包名）或后续段含大写（类名）。"""
    line = m.string
    # 只豁免紧跟在 package / import 关键字后面的那个点分包名本身；同行注释或引号里的 URL 照常检查
    kw = re.match(r"\s*(?:package|import)\s+(?:/\*.*?\*/\s*)?(?:static\s+)?([\w.]+)", line)
    nxt = line[m.end():m.end() + 2]
    as_path = nxt[:1] == ":" or (nxt[:1] == "/" and nxt not in ("/*", "//"))  # `//`、`/*` 是注释不是路径
    if kw and kw.start(1) <= m.start() and m.end() <= kw.end(1) and not as_path:
        return False
    rest = re.match(r"\.([A-Za-z_][\w.]*)", line[m.end():])
    if rest:
        head = m.group(0).split(".", 1)[0]
        if head in _REVERSE_DOMAIN_HEADS or re.search(r"[A-Z]", rest.group(1)):
            return False
    return True


def cn_id_valid(s):
    """中国大陆 18 位身份证号 ISO 7064 mod 11-2 校验码 + 出生年份粗校验。"""
    if len(s) != 18:
        return False
    body, check = s[:17], s[17].upper()
    if not body.isdigit():
        return False
    year = int(s[6:10])
    if year < 1900 or year > 2100:
        return False
    weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
    codes = "10X98765432"
    total = sum(int(body[i]) * weights[i] for i in range(17))
    return codes[total % 11] == check


def looks_random(value):
    """通用高熵密钥判定：长度足够 + 熵足够 + 字符种类够杂 + 不是占位符。"""
    v = value.strip().strip("'\"")
    if len(v) < 20 or len(v) > 200:
        return False
    if PLACEHOLDER_RE.search(v):
        return False
    classes = sum(bool(re.search(p, v)) for p in (r"[a-z]", r"[A-Z]", r"\d"))
    if classes < 2:
        return False
    return shannon_entropy(v) >= 3.5


def mask(s, keep_head=4, keep_tail=2):
    """对命中片段打码：只留首尾少量字符，中间用 * 代替，避免报告本身泄密。"""
    s = s.strip()
    if len(s) <= keep_head + keep_tail:
        return s[0:1] + "*" * (len(s) - 1) if len(s) > 1 else "*"
    return s[:keep_head] + "*" * min(8, len(s) - keep_head - keep_tail) + s[-keep_tail:]


# ── 规则表 ──
# 每条规则：id / 类别 / 严重级 / precise(Python 精确正则,可含 lookaround) /
#           prefilter(rg 安全的召回正则,无 lookaround) / validator(可选,对命中文本二次确认) /
#           group(取第几组作为要打码的敏感片段,0=整体)
SEV_CRIT, SEV_MAJOR, SEV_MINOR = "critical", "major", "minor"
CAT1 = "凭证与密钥"
CAT2 = "个人身份信息(PII)"
CAT3 = "基础设施与内网架构"
CAT4 = "环境上下文与元数据"
CAT5 = "敏感文件名/类型"


def _rule(rid, cat, sev, precise, prefilter, group=0, validator=None):
    return {
        "id": rid, "cat": cat, "sev": sev, "group": group, "validator": validator,
        "precise": re.compile(precise), "prefilter": prefilter,
    }


# 内容规则（逐行匹配）。prefilter 用于 rg union 预筛，必须是 precise 的「超集召回」。
CONTENT_RULES = [
    # —— 类别 1：凭证与密钥（最高风险）——
    _rule("private-key-block", CAT1, SEV_CRIT,
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
          r"-----BEGIN .{0,12}PRIVATE KEY-----"),
    _rule("aws-access-key-id", CAT1, SEV_CRIT,
          r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
          r"(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}"),
    _rule("github-token", CAT1, SEV_CRIT,
          r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b",
          r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}"),
    _rule("slack-token", CAT1, SEV_CRIT,
          r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    _rule("google-api-key", CAT1, SEV_CRIT,
          r"\bAIza[0-9A-Za-z_-]{35}\b", r"AIza[0-9A-Za-z_-]{35}"),
    _rule("gcp-service-account", CAT1, SEV_CRIT,
          r'"type"\s*:\s*"service_account"', r'"type"\s*:\s*"service_account"'),
    _rule("stripe-secret-key", CAT1, SEV_CRIT,
          r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b", r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
    _rule("aliyun-access-key", CAT1, SEV_CRIT,
          r"\bLTAI[0-9A-Za-z]{12,22}\b", r"LTAI[0-9A-Za-z]{12,22}"),
    _rule("tencent-secret-id", CAT1, SEV_CRIT,
          r"\bAKID[0-9A-Za-z]{32}\b", r"AKID[0-9A-Za-z]{32}"),
    _rule("openai-api-key", CAT1, SEV_CRIT,
          r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
          r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ"),
    _rule("anthropic-api-key", CAT1, SEV_CRIT,
          r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}", r"sk-ant-(?:api|admin)\d{2}-"),
    _rule("gitlab-token", CAT1, SEV_CRIT,
          r"\bgl(?:pat|dt|rt|ptt)-[A-Za-z0-9_-]{20,}\b", r"gl(?:pat|dt|rt|ptt)-[A-Za-z0-9_-]{20,}"),
    _rule("npm-token", CAT1, SEV_CRIT,
          r"\bnpm_[A-Za-z0-9]{36}\b", r"npm_[A-Za-z0-9]{36}"),
    _rule("pypi-token", CAT1, SEV_CRIT,
          r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", r"pypi-AgEIcHlwaS5vcmc"),
    _rule("sendgrid-api-key", CAT1, SEV_CRIT,
          r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", r"SG\.[A-Za-z0-9_-]{22}\."),
    _rule("telegram-bot-token", CAT1, SEV_CRIT,
          r"(?<!\d)\d{8,10}:AA[0-9A-Za-z_-]{33}(?![0-9A-Za-z_-])", r"\d{8,10}:AA[0-9A-Za-z_-]{33}"),
    _rule("discord-bot-token", CAT1, SEV_MAJOR,
          r"\b[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}\b",
          r"[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\."),
    _rule("azure-storage-key", CAT1, SEV_CRIT,
          r"(?i)AccountKey=([A-Za-z0-9+/]{80,}={0,2})", r"(?i)AccountKey=", group=1),
    # 群机器人 / Incoming Webhook：拿到 URL 即可冒名发消息
    _rule("chat-webhook-url", CAT1, SEV_MAJOR,
          r"https://(?:hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"
          r"|oapi\.dingtalk\.com/robot/send\?access_token=[a-f0-9]{64}"
          r"|open\.(?:feishu\.cn|larksuite\.com)/open-apis/bot/v2/hook/[0-9a-f-]{36}"
          r"|qyapi\.weixin\.qq\.com/cgi-bin/webhook/send\?key=[0-9a-f-]{36})",
          r"hooks\.slack\.com/services/|oapi\.dingtalk\.com/robot/send|/open-apis/bot/v2/hook/|qyapi\.weixin\.qq\.com/cgi-bin/webhook"),
    _rule("jwt-token", CAT1, SEV_MAJOR,
          r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
          r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _rule("bearer-token", CAT1, SEV_MAJOR,
          r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}=*", r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}", group=0),
    # 连接串里的密码：scheme://user:password@host —— 第 1 组是 password。
    # password 用「贪婪 + 回溯到最后一个 @」匹配，以兼容口令本身含 @（如 P@ssw0rd）；
    # 排除引号/空白防止跨字符串字面量误吞，host 段用 [^/@] 收尾确保停在主机名。
    _rule("db-uri-password", CAT1, SEV_CRIT,
          r"(?i)(?:mysql|postgres(?:ql)?|redis|rediss|mongodb(?:\+srv)?|amqp)://[^:/\s]+:([^\s'\"]{3,})@[^\s'\"/@]+",
          r"(?i)(?:mysql|postgres|redis|mongodb|amqp)://[^:/\s]+:", group=1),
    # 通用高熵密钥：标识符里含 secret/token/password/key 等词，= 一段高熵值 —— 第 1 组是 value，交 looks_random 复核。
    # 用 \w{0,N} 包裹关键词，兼容 SECRET_KEY / myApiToken / db_password 这类常见命名；精度由 looks_random（≥20 位高熵）兜底。
    _rule("generic-secret-assign", CAT1, SEV_MAJOR,
          r"""(?i)\b\w{0,20}(?:secret|passwd|password|pwd|token|api[_-]?key|access[_-]?key|"""
          r"""private[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token)\w{0,12}\s*[:=]\s*['"]?([^\s'"]{20,})['"]?""",
          r"(?i)(?:secret|passwd|password|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token)",
          group=1, validator=lambda m: looks_random(m.group(1))),

    # —— 类别 2：个人身份信息(PII) ——
    _rule("cn-mobile", CAT2, SEV_MAJOR,
          r"(?<!\d)1[3-9]\d{9}(?!\d)", r"1[3-9]\d{9}",
          validator=lambda m: not _in_hex_run(m)),
    _rule("cn-id-card", CAT2, SEV_CRIT,
          r"(?<!\d)\d{17}[\dXx](?!\d)", r"\d{17}[\dXx]",
          validator=lambda m: cn_id_valid(m.group(0)) and not _in_hex_run(m)),
    _rule("bank-card", CAT2, SEV_CRIT,
          r"(?<!\d)\d{13,19}(?!\d)", r"\d{13,19}",
          validator=bank_card_valid),
    _rule("email", CAT2, SEV_MINOR,
          r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
          r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
          validator=lambda m: not re.search(r"(?i)(example\.(com|org)|noreply|no-reply|@test\.|@localhost|your-?email|user@)", m.group(0))),

    # —— 类别 3：基础设施与内网架构 ——
    _rule("private-ipv4", CAT3, SEV_MINOR,
          r"(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)",
          r"(?:10\.|172\.|192\.168\.)\d{1,3}",
          validator=lambda m: m.group(0) not in ("10.0.0.0", "192.168.0.0")),
    _rule("internal-hostname", CAT3, SEV_MAJOR,
          r"\b[a-z0-9][a-z0-9.-]*\.(?:corp|internal|intra|lan|local)\b(?!host)",
          r"\.(?:corp|internal|intra|lan|local)",
          validator=internal_host_valid),
    _rule("mac-address", CAT3, SEV_MINOR,
          r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
          r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}",
          validator=lambda m: m.group(0).lower() not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff")),

    # —— 类别 4：环境上下文与元数据 ——
    # 兼容裸路径 C:\Users\名 与源码 / JSON 里转义的 C:\\Users\\名（1 或 2 个反斜杠）
    _rule("local-user-path", CAT4, SEV_MINOR,
          r"(?:/Users/|/home/|[Cc]:\\{1,2}Users\\{1,2})([^/\\:\s'\"]{2,})",
          r"(?:/Users/|/home/|Users\\)",
          group=1, validator=lambda m: m.group(1).lower() not in GENERIC_USERNAMES),
    # 真 UNC 共享 \\host\share —— 用前瞻排除盘符转义路径 C:\\Users（其前导 \\ 紧跟在 : 之后）
    _rule("smb-share-path", CAT4, SEV_MAJOR,
          r"(?:smb://[^\s'\"]+|(?<![:\w\\])\\\\[A-Za-z0-9._-]+\\[^\s'\"]+)",
          r"(?:smb://|\\\\[A-Za-z0-9._-]+\\)"),
    _rule("sensitive-comment", CAT4, SEV_MINOR,
          r"(?://|#|--|/\*).{0,40}(?:明文|密码盐|盐值|身份证号|手机号明文|银行卡号|plaintext\s*password)",
          r"(?:明文|密码盐|盐值|身份证号|手机号明文|银行卡号|plaintext)"),
]

# 文件名规则：按「文件名」拦截，与内容无关。
FILENAME_RULES = [
    ("dotenv-file", CAT5, SEV_CRIT,
     re.compile(r"(?i)(^|/)\.env(\.[A-Za-z0-9_-]+)?$"),
     lambda name: not re.search(r"(?i)\.(example|sample|template|dist|tpl)$", name)),
    ("key-cert-file", CAT5, SEV_CRIT,
     re.compile(r"(?i)\.(pem|p12|pfx|key|keystore|jks|ppk|kdbx|ovpn|asc)$"), None),
    ("ssh-key-file", CAT5, SEV_CRIT,
     re.compile(r"(?i)(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), None),
    ("token-config-file", CAT5, SEV_MAJOR,
     re.compile(r"(?i)(^|/)(\.npmrc|\.pypirc|\.netrc|\.dockercfg)$"), None),
    ("secret-named-file", CAT5, SEV_MAJOR,
     re.compile(r"(?i)(secret|private|credential|credentials)s?\.(json|xml|ya?ml|properties|conf)$"),
     lambda name: not re.search(r"(?i)(example|sample|template)", name)),
]


# 行内豁免：同一行写 `privacy-guard:allow`（全部规则）或 `privacy-guard:allow rule-a,rule-b`（指定规则）
INLINE_ALLOW_RE = re.compile(r"privacy-guard:allow\b(?:[ \t]+([a-z0-9][a-z0-9,_-]*))?")
# 被豁免 / 基线接纳的数量，写进报告，豁免不悄悄发生
SUPPRESSED = {"inline": 0, "config": 0, "baseline": 0}
# 豁免明细（已打码），报告里单列「已豁免」，便于审计每一条豁免
SUPPRESSED_ITEMS = []
# Markdown 报告最多列出的豁免条数（钩子把报告塞进提示与输出缓冲区，不能无限长）
MAX_SUPPRESSED_ROWS = 200


def _suppress(kind, f, reason=""):
    SUPPRESSED[kind] += 1
    SUPPRESSED_ITEMS.append({"kind": kind, "rule": f["rule"], "path": f["path"], "line": f.get("line", 0),
                             "commit": f.get("commit", ""), "match": f["match"], "reason": reason})


def fingerprint(rule_id, secret):
    """命中项指纹：规则 + 明文的 sha256 前 16 位。不含明文，路径无关（文件挪动、历史与工作区同一份密钥指纹相同）。"""
    return hashlib.sha256(("%s\0%s" % (rule_id, secret)).encode("utf-8", "replace")).hexdigest()[:16]


def classify_line(path, lineno, line):
    """对一行文本套用全部内容规则，返回 finding 列表（已打码）。"""
    out = []
    if len(line) > 4000:  # 跳过超长行（多为压缩/编码数据），避免灾难性回溯
        return out
    inline = INLINE_ALLOW_RE.search(line)
    inline_rules = set(inline.group(1).split(",")) if inline and inline.group(1) else None
    for rule in CONTENT_RULES:
        for m in rule["precise"].finditer(line):
            if rule["validator"] and not rule["validator"](m):
                continue
            secret = m.group(rule["group"]) or m.group(0)
            if PLACEHOLDER_RE.fullmatch(secret.strip().strip("'\"")):
                continue
            f = {
                "rule": rule["id"], "category": rule["cat"], "severity": rule["sev"],
                "path": path, "line": lineno, "match": mask(secret),
                "fingerprint": fingerprint(rule["id"], secret.strip()),
            }
            if inline and (inline_rules is None or rule["id"] in inline_rules):
                _suppress("inline", f, "行内 privacy-guard:allow")
                continue
            out.append(f)
    return out


def check_filename(path):
    """对文件名套用文件名规则。"""
    norm = path.replace("\\", "/")
    base = norm.rsplit("/", 1)[-1]
    out = []
    for rid, cat, sev, rx, extra in FILENAME_RULES:
        if rx.search(norm) and (extra is None or extra(base)):
            out.append({"rule": rid, "category": cat, "severity": sev,
                        "path": path, "line": 0, "match": base,
                        "fingerprint": fingerprint(rid, _plain_path(norm))})
    return out


def is_binary(sample):
    return b"\x00" in sample


def iter_all_files(root):
    """完整枚举工作区文件名：跳过噪声目录；保留 .gitignore 忽略的文件
    （.env、私钥这类常被 gitignore，恰恰最该查）。用于文件名规则与内容兜底。"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in NOISE_DIRS]
        for fn in filenames:
            yield os.path.join(dirpath, fn)


def _rg_candidate_files(root):
    """用 ripgrep 一次性筛出「可能命中任意内容规则」的候选文件（召回优先）。
    返回 None 表示 rg 不可用，调用方退化为全量遍历。"""
    from shutil import which
    if not which("rg"):
        return None
    union = "|".join("(?:%s)" % r["prefilter"] for r in CONTENT_RULES)
    cmd = ["rg", "--no-ignore", "--hidden", "--files-with-matches",
           "--null", "-e", union]
    for d in NOISE_DIRS:
        cmd += ["-g", "!%s" % d]
    # 显式把搜索根当作路径参数传给 rg：某些嵌套子进程环境（如经 Node 派生 python，
    # 插件的 MCP / hook 即如此）下 rg 不採用 subprocess 的 cwd、会在错误目录里搜出空结果，
    # 静默漏掉真泄露。显式路径不踩这个坑（cwd 仍保留，二者一致）。
    cmd.append(root)
    try:
        res = subprocess.run(cmd, cwd=root, capture_output=True, timeout=120)
    except Exception:
        return None
    if res.returncode not in (0, 1):  # 0=有命中 1=无命中；其余视为失败
        return None
    files = [f for f in res.stdout.decode("utf-8", "replace").split("\0") if f]
    return [os.path.join(root, f) for f in files]


def scan_worktree(root):
    findings = []
    all_files = list(iter_all_files(root))
    # 文件名规则：对所有文件都查（.pem/.env 等靠文件名定罪，与内容无关，绝不能被内容预筛漏掉）
    for path in all_files:
        rel = os.path.relpath(path, root).replace("\\", "/")
        findings += check_filename(rel)
    # 内容规则：有 rg 就只深扫「可能命中」的候选文件，否则全量扫
    candidates = _rg_candidate_files(root)
    if candidates is None:
        candidates = all_files
    for path in candidates:
        rel = os.path.relpath(path, root).replace("\\", "/")
        try:
            if os.path.getsize(path) > MAX_FILE_BYTES:
                continue
            with open(path, "rb") as f:
                raw = f.read()
            if is_binary(raw[:8192]):
                continue
            text = raw.decode("utf-8", "replace")
        except (OSError, ValueError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            findings += classify_line(rel, i, line)
    return findings


def _git(root, args):
    return subprocess.run(["git", "-C", root] + args, capture_output=True)


def scan_history(root):
    """扫全量 git 历史：按 blob 去重，每份唯一内容只扫一次；命中后定位引入提交。"""
    if _git(root, ["rev-parse", "--git-dir"]).returncode != 0:
        return [], False
    res = _git(root, ["rev-list", "--all", "--objects"])
    if res.returncode != 0:
        return [], False
    blobs = OrderedDict()  # blob_sha -> 代表性路径
    for ln in res.stdout.decode("utf-8", "replace").splitlines():
        parts = ln.split(" ", 1)
        if len(parts) == 2 and parts[1].strip():
            blobs.setdefault(parts[0], parts[1].strip())
    findings = []
    for sha, path in blobs.items():
        rel = path.replace("\\", "/")
        findings += check_filename("[history] " + rel)
        cat = _git(root, ["cat-file", "blob", sha])
        if cat.returncode != 0:
            continue
        raw = cat.stdout
        if len(raw) > MAX_FILE_BYTES or is_binary(raw[:8192]):
            continue
        text = raw.decode("utf-8", "replace")
        hits = []
        sup_from = len(SUPPRESSED_ITEMS)
        for i, line in enumerate(text.splitlines(), 1):
            hits += classify_line(rel, i, line)
        if hits or len(SUPPRESSED_ITEMS) > sup_from:
            commit = _history_commit_for_blob(root, sha)
            # 行内豁免明细同样标上 [history] 与提交号，便于审计
            for h in hits + SUPPRESSED_ITEMS[sup_from:]:
                h["path"] = "[history] %s" % rel
                h["commit"] = commit
            findings += hits
    return findings, True


def _history_commit_for_blob(root, sha):
    """用 --find-object 定位「引入该 blob」的提交（findings 通常很少，按需查询不拖累整体）。"""
    res = _git(root, ["log", "--all", "--format=%h", "--find-object", sha, "-1"])
    if res.returncode == 0:
        line = res.stdout.decode("utf-8", "replace").strip().splitlines()
        if line:
            return line[0]
    return "(未定位)"


def scan_staged(root):
    """扫 git 暂存区（pre-commit 钩子用）：只看本次将提交的新增内容。"""
    res = _git(root, ["diff", "--cached", "--unified=0", "--no-color"])
    if res.returncode != 0:
        return []
    findings, cur = [], "(staged)"
    lineno = 0
    for ln in res.stdout.decode("utf-8", "replace").splitlines():
        if ln.startswith("+++ b/"):
            cur = ln[6:]
        elif ln.startswith("@@"):
            m = re.search(r"\+(\d+)", ln)
            lineno = int(m.group(1)) if m else 0
        elif ln.startswith("+") and not ln.startswith("+++"):
            findings += classify_line(cur, lineno, ln[1:])
            lineno += 1
    # 暂存区文件名拦截
    names = _git(root, ["diff", "--cached", "--name-only", "--diff-filter=AM"])
    if names.returncode == 0:
        for n in names.stdout.decode("utf-8", "replace").splitlines():
            findings += check_filename(n)
    return findings


def scan_range(root, since, until="HEAD"):
    """扫提交区间 since..until 里**新增**的内容（PR / 上个 tag 以来）：只看各提交的新增行与新增/修改的文件名，并标出提交。"""
    if _git(root, ["rev-parse", "--git-dir"]).returncode != 0:
        return [], False
    # quotePath=false：中文等路径不加引号。合并提交用 --cc（老版本 Git 也支持）：只把相对**所有**父提交都是新增的内容
    # 算作本区间新增（即解决冲突时写入的内容），把目标分支同步进功能分支时带进来的既有内容不算
    git_args = ["-c", "core.quotePath=false", "log", "--no-color", "--no-ext-diff", "--no-renames", "--cc",
                "%s..%s" % (since, until)]
    res = _git(root, git_args[:3] + ["--unified=0", "--format=@@privacy-guard-commit %h"] + git_args[3:])
    names = _git(root, git_args[:3] + ["--name-only", "--diff-filter=AMC", "--format=@@privacy-guard-commit %h"] + git_args[3:])
    if res.returncode != 0 or names.returncode != 0:
        return [], False
    findings, commit = [], ""
    # 文件名单独从 --name-only 取：二进制文件与新建空文件没有 +++ 头，但同样要查（如 .p12、空 .env）
    for ln in names.stdout.decode("utf-8", "replace").splitlines():
        if ln.startswith("@@privacy-guard-commit "):
            commit = ln[len("@@privacy-guard-commit "):]
        elif ln.strip():
            for f in check_filename(ln.strip()):
                f["commit"] = commit
                findings.append(f)
    commit, cur, lineno, width = "", None, 0, 1
    for ln in res.stdout.decode("utf-8", "replace").splitlines():
        if ln.startswith("@@privacy-guard-commit "):
            commit = ln[len("@@privacy-guard-commit "):]
        elif ln.startswith("+++ "):
            # 未加引号且含空格的路径，Git 会在行尾补一个制表符
            tgt = ln[4:].rstrip("\t")
            if tgt.startswith('"') and tgt.endswith('"'):
                tgt = tgt[1:-1]
            cur = tgt[2:] if tgt.startswith("b/") else None
        elif ln.startswith("@@"):
            # 普通提交 @@ -a +b @@（1 列前缀）；合并提交 @@@ -a -b +c @@@（每个父提交一列前缀）
            width = len(ln) - len(ln.lstrip("@")) - 1
            m = re.search(r"\+(\d+)", ln)
            lineno = int(m.group(1)) if m else 0
        elif cur and len(ln) >= width and ln[:width].strip("+ ") == "" and "+" in ln[:width]:
            if ln[:width] == "+" * width:
                sup_from = len(SUPPRESSED_ITEMS)
                for f in classify_line(cur, lineno, ln[width:]):
                    f["commit"] = commit
                    findings.append(f)
                for f in SUPPRESSED_ITEMS[sup_from:]:
                    f["commit"] = commit
            lineno += 1
    return findings, True


# ── 项目配置（.privacy-guard.json）与基线 ──
CONFIG_NAME = ".privacy-guard.json"
SEV_LEVELS = (SEV_CRIT, SEV_MAJOR, SEV_MINOR)


class ConfigError(Exception):
    pass


def _plain_path(p):
    return p.replace("\\", "/").split("] ", 1)[-1] if p.startswith("[") else p.replace("\\", "/")


def _glob_hit(path, patterns):
    path = _plain_path(path)
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(path, g.rstrip("/") + "/*") for g in patterns)


def load_config(root, explicit=None):
    """读项目配置；无文件返回空配置。字段：ignore_paths / allow / severity / rules / baseline / fail_on。"""
    path = explicit or os.path.join(root, CONFIG_NAME)
    if not os.path.isfile(path):
        if explicit:
            raise ConfigError("找不到配置文件：%s" % explicit)
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except ValueError as e:
        raise ConfigError("%s 不是合法 JSON：%s" % (path, e))
    if not isinstance(cfg, dict):
        raise ConfigError("%s 顶层必须是对象" % path)
    for i, a in enumerate(cfg.get("allow", [])):
        if not isinstance(a, dict) or not a.get("reason"):
            raise ConfigError("allow[%d] 必须写 reason（豁免要说明理由）" % i)
        if not (a.get("rule") or a.get("path") or a.get("fingerprint")):
            raise ConfigError("allow[%d] 至少要指定 rule / path / fingerprint 之一" % i)
    if cfg.get("fail_on") not in (None,) + SEV_LEVELS + ("never",):
        raise ConfigError("fail_on 只能是 critical/major/minor/never")
    for rid, sev in (cfg.get("severity") or {}).items():
        if sev not in SEV_LEVELS + ("off",):
            raise ConfigError("severity.%s 只能是 critical/major/minor/off" % rid)
    for r in cfg.get("rules", []):
        if not r.get("id") or not r.get("pattern"):
            raise ConfigError("自定义规则必须有 id 与 pattern")
        if r.get("severity", SEV_MAJOR) not in SEV_LEVELS:
            raise ConfigError("规则 %s 的 severity 只能是 critical/major/minor" % r["id"])
        try:
            CONTENT_RULES.append(_rule(r["id"], r.get("category", CAT1), r.get("severity", SEV_MAJOR),
                                       r["pattern"], r.get("prefilter", r["pattern"]), group=int(r.get("group", 0))))
        except re.error as e:
            raise ConfigError("规则 %s 的 pattern 无法编译：%s" % (r["id"], e))
    return cfg


def _allow_hit(f, a):
    rules = a.get("rule")
    if rules and f["rule"] not in ([rules] if isinstance(rules, str) else rules):
        return False
    if a.get("path") and not _glob_hit(f["path"], [a["path"]] if isinstance(a["path"], str) else a["path"]):
        return False
    if a.get("fingerprint") and f.get("fingerprint") != a["fingerprint"]:
        return False
    return True


def apply_config(findings, cfg):
    ignore = cfg.get("ignore_paths") or []
    allow = cfg.get("allow") or []
    sev = cfg.get("severity") or {}
    out = []
    for f in findings:
        if sev.get(f["rule"]) == "off":
            _suppress("config", f, "severity: off")
            continue
        if ignore and _glob_hit(f["path"], ignore):
            _suppress("config", f, "ignore_paths")
            continue
        hit = next((a for a in allow if _allow_hit(f, a)), None)
        if hit is not None:
            _suppress("config", f, "allow：" + str(hit.get("reason", "")))
            continue
        if f["rule"] in sev:
            f["severity"] = sev[f["rule"]]
        out.append(f)
    return out


def load_baseline(path):
    if not path or not os.path.isfile(path):
        return set()
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except ValueError as e:
        raise ConfigError("基线 %s 不是合法 JSON：%s" % (path, e))
    return {x["fingerprint"] for x in data.get("findings", []) if x.get("fingerprint")}


def write_baseline(path, findings):
    """基线只存指纹、规则与路径，不存片段（打码片段配合无盐指纹可穷举还原手机号等低熵信息）。"""
    items = OrderedDict()
    for f in sorted(findings, key=lambda x: (x["rule"], _plain_path(x["path"]))):
        items.setdefault(f["fingerprint"], {"fingerprint": f["fingerprint"], "rule": f["rule"],
                                             "severity": f["severity"], "path": _plain_path(f["path"])})
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"version": 1, "tool": "privacy-guard", "findings": list(items.values())},
                  fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    return len(items)


SARIF_LEVEL = {SEV_CRIT: "error", SEV_MAJOR: "warning", SEV_MINOR: "note"}


def build_sarif(findings):
    """SARIF 2.1.0：可上传 GitHub Code Scanning；片段仍打码，history/range 命中在消息里带提交。"""
    rules = OrderedDict()
    results = []
    for f in findings:
        rules.setdefault(f["rule"], {"id": f["rule"], "name": f["rule"],
                                     "shortDescription": {"text": "%s：%s" % (f["category"], f["rule"])},
                                     "properties": {"tags": ["security", "privacy"]}})
        loc = {"artifactLocation": {"uri": _plain_path(f["path"])}}
        if f.get("line"):
            loc["region"] = {"startLine": f["line"]}
        msg = "%s %s：%s" % (SEV_NAME[f["severity"]], f["category"], f["match"])
        if f.get("commit"):
            msg += "（提交 %s）" % f["commit"]
        results.append({"ruleId": f["rule"], "level": SARIF_LEVEL[f["severity"]], "message": {"text": msg},
                        "locations": [{"physicalLocation": loc}],
                        "partialFingerprints": {"privacyGuard/v1": f.get("fingerprint", "")}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "privacy-guard", "informationUri": "https://github.com/wcpe/privacy-guard-skill",
                                          "rules": list(rules.values())}},
                      "results": results}]}


def exit_code(counts, fail_on):
    """2=critical / 1=major（及 fail_on=minor 时的 minor）/ 0；低于 fail_on 门槛的不计。"""
    if fail_on == "never":
        return 0
    if counts[SEV_CRIT]:
        return 2
    if counts[SEV_MAJOR] and fail_on in (SEV_MAJOR, SEV_MINOR):
        return 1
    if counts[SEV_MINOR] and fail_on == SEV_MINOR:
        return 1
    return 0


SEV_ORDER = {SEV_CRIT: 0, SEV_MAJOR: 1, SEV_MINOR: 2}
SEV_ICON = {SEV_CRIT: "🔴", SEV_MAJOR: "🟡", SEV_MINOR: "🟢"}
SEV_NAME = {SEV_CRIT: "critical", SEV_MAJOR: "major", SEV_MINOR: "minor"}


def dedupe(findings):
    """按 (路径,行,打码片段) 去重，保留最严重的一条——
    避免同一明文被「专用规则 + 通用规则」重复刷屏，也避免历史里同份内容反复出现。"""
    best = OrderedDict()
    for f in findings:
        k = (f["path"], f.get("line", 0), f["match"])
        if k not in best or SEV_ORDER[f["severity"]] < SEV_ORDER[best[k]["severity"]]:
            best[k] = f
    return list(best.values())


def build_report(findings, scope):
    findings = dedupe(findings)
    findings.sort(key=lambda f: (SEV_ORDER[f["severity"]], f["category"], f["path"]))
    counts = {SEV_CRIT: 0, SEV_MAJOR: 0, SEV_MINOR: 0}
    for f in findings:
        counts[f["severity"]] += 1
    lines = ["# 隐私/敏感数据扫描报告", "",
             "- 范围：%s" % scope,
             "- 结论：%s" % ("🔴 发现 %d 项致命泄露，必须处理" % counts[SEV_CRIT]
                            if counts[SEV_CRIT] else
                            ("🟡 发现 %d 项疑似泄露，建议核实" % counts[SEV_MAJOR]
                             if counts[SEV_MAJOR] else
                             ("🟢 仅 %d 项低风险提示" % counts[SEV_MINOR]
                              if counts[SEV_MINOR] else "✅ 未发现敏感数据"))),
             "- 统计：🔴 critical %d · 🟡 major %d · 🟢 minor %d · 合计 %d"
             % (counts[SEV_CRIT], counts[SEV_MAJOR], counts[SEV_MINOR], len(findings)),
             ] + (["- 已豁免：行内 %d · 配置 %d · 基线接纳 %d（豁免项不计入上面的统计）"
                   % (SUPPRESSED["inline"], SUPPRESSED["config"], SUPPRESSED["baseline"])]
                  if any(SUPPRESSED.values()) else []) + [
             "", "> 所有命中片段均已打码；明文请到对应位置核对。本报告应留在 .tmp/ 不要入库。", ""]
    if findings:
        lines += ["| # | 级别 | 类别 | 规则 | 位置 | 打码片段 |", "|---|---|---|---|---|---|"]
        for i, f in enumerate(findings, 1):
            loc = f["path"] + (":%d" % f["line"] if f.get("line") else "")
            if f.get("commit"):
                loc += " @ " + f["commit"]
            lines.append("| %d | %s %s | %s | `%s` | %s | `%s` |"
                         % (i, SEV_ICON[f["severity"]], SEV_NAME[f["severity"]],
                            f["category"], f["rule"], loc, f["match"]))
    if SUPPRESSED_ITEMS:
        lines += ["", "## 已豁免（不计入统计，供审计）", "",
                  "| # | 方式 | 规则 | 位置 | 打码片段 | 理由 |", "|---|---|---|---|---|---|"]
        for i, f in enumerate(SUPPRESSED_ITEMS[:MAX_SUPPRESSED_ROWS], 1):
            loc = f["path"] + (":%d" % f["line"] if f.get("line") else "")
            if f.get("commit"):
                loc += " @ " + f["commit"]
            reason = f["reason"].replace("|", "\\|").replace("\n", " ")
            lines.append("| %d | %s | `%s` | %s | `%s` | %s |"
                         % (i, f["kind"], f["rule"], loc, f["match"], reason))
        if len(SUPPRESSED_ITEMS) > MAX_SUPPRESSED_ROWS:
            lines.append("")
            lines.append("> 另有 %d 条豁免未列出，完整明细见 `--format json` 的 `suppressed_items`。"
                         % (len(SUPPRESSED_ITEMS) - MAX_SUPPRESSED_ROWS))
    return "\n".join(lines) + "\n", counts, findings


def main():
    # Windows 控制台默认 GBK，强制 stdout/stderr 走 UTF-8 以便打印中文与 emoji
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="隐私/敏感数据检测引擎")
    ap.add_argument("--mode", choices=["worktree", "history", "staged", "range", "all"],
                    default=None, help="扫描范围（默认 all；给了 --since 时默认 range）")
    ap.add_argument("--path", default=".", help="项目根目录")
    ap.add_argument("--since", default=None, help="range 模式起点（tag / 分支 / 提交），扫 since..until 的新增内容")
    ap.add_argument("--until", default="HEAD", help="range 模式终点，默认 HEAD")
    ap.add_argument("--format", choices=["md", "json", "both", "sarif"], default="both")
    ap.add_argument("--out", default=None, help="报告输出文件前缀（不含扩展名）")
    ap.add_argument("--config", default=None, help="项目配置，默认 <项目根>/%s（不存在则忽略）" % CONFIG_NAME)
    ap.add_argument("--baseline", default=None, help="基线文件：其中的已知命中不再计入（默认取配置里的 baseline）")
    ap.add_argument("--no-baseline", action="store_true", help="忽略基线，报出全部命中")
    ap.add_argument("--write-baseline", default=None, metavar="FILE",
                    help="把本次全部命中写成基线（只含指纹、规则与路径）后以 0 退出")
    ap.add_argument("--fail-on", choices=["critical", "major", "minor", "never"], default=None,
                    help="从哪一级开始给非 0 退出码（默认 major：critical→2、major→1）")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    mode = args.mode or ("range" if args.since else "all")
    if mode == "range" and not args.since:
        ap.error("--mode range 需要 --since <ref>")
    try:
        cfg = load_config(root, args.config)
        baseline_path = None if args.no_baseline or args.write_baseline else (args.baseline or cfg.get("baseline"))
        if baseline_path and not os.path.isabs(baseline_path):
            baseline_path = os.path.join(root, baseline_path)
        known = load_baseline(baseline_path)
    except ConfigError as e:
        sys.stderr.write("[privacy-guard] 配置错误：%s\n" % e)
        sys.exit(3)
    fail_on = args.fail_on or cfg.get("fail_on") or SEV_MAJOR

    findings, git_ok = [], None
    if mode in ("worktree", "all"):
        findings += scan_worktree(root)
    if mode in ("history", "all"):
        hist, git_ok = scan_history(root)
        findings += hist
    if mode == "staged":
        findings += scan_staged(root)
    if mode == "range":
        rng, git_ok = scan_range(root, args.since, args.until)
        if not git_ok:
            # 区间扫描多用作门禁：区间无效不能静默当成「干净」放行
            sys.stderr.write("[privacy-guard] 无法扫描区间 %s..%s：不是 git 仓库或 ref 不存在\n" % (args.since, args.until))
            sys.exit(3)
        findings += rng

    findings = apply_config(dedupe(findings), cfg)
    if args.write_baseline:
        n = write_baseline(args.write_baseline, findings)
        sys.stdout.write("[privacy-guard] 已把 %d 项命中写入基线 %s（只含指纹、规则与路径）\n" % (n, args.write_baseline))
        sys.exit(0)
    if known:
        kept = []
        for f in findings:
            if f.get("fingerprint") in known:
                _suppress("baseline", f, "基线已接纳")
            else:
                kept.append(f)
        findings = kept

    scope = mode + (" %s..%s" % (args.since, args.until) if mode == "range" else "")
    if mode in ("history", "all") and git_ok is False:
        scope += "（非 git 仓库或区间无效，已跳过 git 扫描）"
    report, counts, findings = build_report(findings, scope)

    def emit(ext, text):
        if args.out:
            with open(args.out + ext, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)

    if args.format in ("md", "both"):
        emit(".md", report)
    if args.format in ("json", "both"):
        payload = {"scope": scope, "counts": counts, "suppressed": dict(SUPPRESSED),
                   "suppressed_items": SUPPRESSED_ITEMS, "fail_on": fail_on,
                   "findings": findings}
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out:
            emit(".json", text)
        elif args.format == "json":
            emit(".json", text + "\n")
    if args.format == "sarif":
        emit(".sarif", json.dumps(build_sarif(findings), ensure_ascii=False, indent=2) + "\n")

    sys.exit(exit_code(counts, fail_on))


if __name__ == "__main__":
    main()
