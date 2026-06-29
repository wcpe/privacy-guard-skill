---
description: 只扫 git 全量历史（查"以前提交过后来删了"，走 privacy-guard）
---

扫描 **git 全量历史**有没有残留的敏感数据（删了文件 ≠ 安全）。用 **privacy-guard** 技能、`mode=history`：按 blob 去重、定位涉及提交。命中后**第一动作永远是轮换 / 吊销密钥**，清历史只是止血——给指引但**不替我改写历史 / force-push**。
