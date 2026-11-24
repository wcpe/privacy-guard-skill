#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""给当前 git 仓库装 privacy-guard pre-commit 拦截钩子（自包含：引擎副本 + 钩子脚本）。

自动识别钩子目录：core.hooksPath（含 husky）> git rev-parse --git-path hooks（兼容 worktree / 子模块）。
已有非本工具的 pre-commit 时不覆盖：改为写入 pre-commit.privacy-guard 并提示如何串联。
只改钩子目录，不动工作区与历史。
"""
import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SKILL = os.path.dirname(HERE)
MARK = "privacy-guard 提交前拦截钩子"


def git(root, *a):
    r = subprocess.run(["git", "-C", root] + list(a), capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(description="安装 privacy-guard pre-commit 钩子")
    ap.add_argument("--path", default=".", help="目标仓库（默认当前目录）")
    ap.add_argument("--force", action="store_true", help="已有其他 pre-commit 时也覆盖（先备份为 pre-commit.bak）")
    args = ap.parse_args()

    root = git(os.path.abspath(args.path), "rev-parse", "--show-toplevel")
    if not root:
        sys.exit("[privacy-guard] %s 不是 git 仓库" % args.path)
    custom = git(root, "config", "core.hooksPath")
    hooks = os.path.join(root, custom) if custom and not os.path.isabs(custom) else custom
    if not hooks:
        hooks = git(root, "rev-parse", "--git-path", "hooks")
        hooks = hooks if os.path.isabs(hooks) else os.path.join(root, hooks)
    os.makedirs(hooks, exist_ok=True)

    shutil.copyfile(os.path.join(HERE, "scan.py"), os.path.join(hooks, "privacy_scan.py"))
    src = os.path.join(SKILL, "assets", "pre-commit")
    target = os.path.join(hooks, "pre-commit")
    note = ""
    if os.path.exists(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            ours = MARK in f.read()
        if not ours and not args.force:
            target = os.path.join(hooks, "pre-commit.privacy-guard")
            note = ("已有其他 pre-commit 钩子，未覆盖。请在它末尾加一行串联：\n"
                    "  sh \"$(dirname \"$0\")/pre-commit.privacy-guard\" || exit 1")
        elif not ours:
            shutil.copyfile(target, target + ".bak")
            note = "原 pre-commit 已备份为 pre-commit.bak"
    shutil.copyfile(src, target)
    os.chmod(target, 0o755)
    print("[privacy-guard] 钩子已装到 %s" % target)
    if custom:
        print("  （按 core.hooksPath=%s 安装；husky 等工具管理的目录请把改动一并提交）" % custom)
    if note:
        print("  " + note)
    print("  只挡新提交，挡不住历史旧泄露；可被 git commit --no-verify 绕过，团队级约束请配 CI 扫描。")


if __name__ == "__main__":
    main()
