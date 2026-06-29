---
description: 只扫即将提交的暂存内容（提交前自查，走 privacy-guard）
---

扫描 git **暂存区**（本次将提交的新增内容）有没有敏感数据。用 **privacy-guard** 技能、`mode=staged`：命中 🔴 critical 必须在提交前移除 / 脱敏。**只检测不改写**。
