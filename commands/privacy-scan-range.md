---
description: 只扫某个区间新增的内容（PR / 上个版本以来，走 privacy-guard）
argument-hint: "<起点 ref：base 分支或上个 tag>"
---

扫描 `$ARGUMENTS..HEAD` 各提交**新增**的内容有没有敏感数据。用 **privacy-guard** 技能、`--since $ARGUMENTS`（range 模式）：结果带提交号，读项目 `.privacy-guard.json` 与基线；没给起点时先问我（一般是 PR 的 base 分支或上个发布 tag）。**只检测不改写**。
