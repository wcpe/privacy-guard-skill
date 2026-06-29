---
description: 装 git pre-commit 拦截钩子（提交前自动扫暂存区，走 privacy-guard）
---

按 **privacy-guard** 技能第 5 步，给当前仓库装 **git pre-commit** 拦截钩子：把 `scan.py` 与 `assets/pre-commit` 拷进 `.git/hooks/`，命中 critical 时挡下提交。装前说明：此钩子保护**任何人**（含终端外提交）、但只挡**新提交**、挡不住历史旧泄露；本地钩子可被 `--no-verify` 绕过，团队级强约束要配 CI 扫描。

> 与插件自带的 Claude Code 提交门是两层：CC 提交门只在 Claude 会话里发起的提交时生效；这个 git 钩子覆盖该仓库所有提交。两者互补。
