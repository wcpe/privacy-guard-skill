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


def bank_card_valid(m):
    """银行卡校验：Luhn 通过，且排除两类高频「数字串」误报 ——
    ① 浮点小数尾数：命中串紧邻前缀为 `<数字>.`（如 Prometheus 指标 20.00242334472774 的小数部分）；
    ② 14 位 yyyymmddhhmmss 时间戳（Go 伪版本号 / go.sum 哈希行 / 日志时间戳）。
    Luhn 无法区分这些串与真实卡号（任意 14 位串约 1/10 撞中），故以语义守卫补足精度。"""
    num = m.group(0)
    if not luhn_valid(num):
        return False
    if _is_datetime14(num):
        return False
    if re.search(r"\d\.$", m.string[:m.start()]):
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
          r"(?<!\d)1[3-9]\d{9}(?!\d)", r"1[3-9]\d{9}"),
    _rule("cn-id-card", CAT2, SEV_CRIT,
          r"(?<!\d)\d{17}[\dXx](?!\d)", r"\d{17}[\dXx]",
          validator=lambda m: cn_id_valid(m.group(0))),
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
          r"\.(?:corp|internal|intra|lan|local)"),
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


def classify_line(path, lineno, line):
    """对一行文本套用全部内容规则，返回 finding 列表（已打码）。"""
    out = []
    if len(line) > 4000:  # 跳过超长行（多为压缩/编码数据），避免灾难性回溯
        return out
    for rule in CONTENT_RULES:
        for m in rule["precise"].finditer(line):
            if rule["validator"] and not rule["validator"](m):
                continue
            secret = m.group(rule["group"]) or m.group(0)
            if PLACEHOLDER_RE.fullmatch(secret.strip().strip("'\"")):
                continue
            out.append({
                "rule": rule["id"], "category": rule["cat"], "severity": rule["sev"],
                "path": path, "line": lineno, "match": mask(secret),
            })
    return out


def check_filename(path):
    """对文件名套用文件名规则。"""
    norm = path.replace("\\", "/")
    base = norm.rsplit("/", 1)[-1]
    out = []
    for rid, cat, sev, rx, extra in FILENAME_RULES:
        if rx.search(norm) and (extra is None or extra(base)):
            out.append({"rule": rid, "category": cat, "severity": sev,
                        "path": path, "line": 0, "match": base})
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
        for i, line in enumerate(text.splitlines(), 1):
            hits += classify_line(rel, i, line)
        if hits:
            commit = _history_commit_for_blob(root, sha)
            for h in hits:
                h["path"] = "[history] %s" % rel
                h["commit"] = commit
            findings += hits
    return findings, True


def _history_commit_for_blob(root, sha):
    """用 --find-object 定位「引入该 blob」的提交（findings 通常很少，按需查询不拖累整体）。"""
    res = _git(root, ["log", "--all", "--oneline", "--find-object", sha, "-1"])
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
    return "\n".join(lines) + "\n", counts, findings


def main():
    # Windows 控制台默认 GBK，强制 stdout/stderr 走 UTF-8 以便打印中文与 emoji
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="隐私/敏感数据检测引擎")
    ap.add_argument("--mode", choices=["worktree", "history", "staged", "all"],
                    default="all", help="扫描范围")
    ap.add_argument("--path", default=".", help="项目根目录")
    ap.add_argument("--format", choices=["md", "json", "both"], default="both")
    ap.add_argument("--out", default=None, help="报告输出文件前缀（不含扩展名）")
    args = ap.parse_args()

    root = os.path.abspath(args.path)
    findings, history_ok = [], None
    if args.mode in ("worktree", "all"):
        findings += scan_worktree(root)
    if args.mode in ("history", "all"):
        hist, history_ok = scan_history(root)
        findings += hist
    if args.mode == "staged":
        findings += scan_staged(root)

    scope = args.mode + (
        "（非 git 仓库，已跳过历史扫描）" if args.mode in ("history", "all")
        and history_ok is False else "")
    report, counts, findings = build_report(findings, scope)

    if args.format in ("md", "both"):
        if args.out:
            with open(args.out + ".md", "w", encoding="utf-8") as f:
                f.write(report)
        else:
            sys.stdout.write(report)
    if args.format in ("json", "both"):
        payload = {"scope": scope, "counts": counts, "findings": findings}
        text = json.dumps(payload, ensure_ascii=False, indent=2)
        if args.out:
            with open(args.out + ".json", "w", encoding="utf-8") as f:
                f.write(text)
        elif args.format == "json":
            sys.stdout.write(text + "\n")

    # 退出码：有 critical→2，有 major→1，否则 0（供 pre-commit 钩子据此拦截）
    sys.exit(2 if counts[SEV_CRIT] else (1 if counts[SEV_MAJOR] else 0))


if __name__ == "__main__":
    main()
