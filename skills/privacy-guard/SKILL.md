---
name: privacy-guard
description: 检测当前项目工作区与 git 历史中是否硬编码了隐私/敏感数据(凭证密钥、PII、内网架构、环境元数据、敏感文件)时使用。当用户说"扫一下有没有泄露密钥/隐私、提交前查敏感信息、检查 git 历史有没有密码、有没有硬编码 token/身份证/内网IP、开源/交付前脱敏自查、防止把 .env/私钥提交上去、装个提交前拦截钩子防泄密、secret scanning、敏感信息检测"时触发——即使没明说"隐私扫描"。捆绑 rg+Python 检测引擎(正则+熵值+Luhn/身份证校验+白名单降误报),扫工作区与全量 git 历史,产出**脱敏**分级报告 + 按类修复指引(含历史清除与密钥轮换),可选安装 pre-commit 拦截钩子。**只检测、只报告、给指引——绝不自动改写历史或吊销密钥**。
---

# 隐私数据检测（privacy-guard）

## 核心原则

隐私扫描 = **找出敏感数据 + 分级报告 + 给修复指引**，三条命脉：

1. **检测 / 修复分离** —— 本技能只**检测 + 报告 + 指引**，绝不替用户改写 git 历史、force-push、删文件、轮换/吊销密钥。这些操作不可逆、且常牵动远端与团队，必须由用户知情后亲自执行（同 `sdd-review-code` 的审 / 修分离）。
2. **报告自身不能成为新泄露** —— 命中片段一律**打码**展示，报告写进 `.tmp/`（**不入库**）。把明文密钥贴进对话或入库的报告，等于又泄一次。
3. **误报可控，但凭证类宁可多报** —— 用熵值 / Luhn / 身份证校验 / 白名单压低噪声；但**凭证与密钥类一旦疑似就报出来让人核实**——漏掉一把真密钥的代价，远高于多看一眼误报。

## 适用边界

- 查的是「**敏感数据有没有被硬编码进代码或 git 历史**」——区别于 `sdd-review-code`（审代码质量 / bug）。两者可叠加：review 顺带发现的硬编码密钥，正是本技能的主场。
- **任意项目可用**，不要求是 SDD 项目（无需 `docs/PRD.md`）。在 SDD 项目里，可作为 `sdd-accept-phase` / `sdd-release-version` 发版前的一道闸。
- 一旦敏感数据进过 git 历史或推过远端，**必须当作「已泄露」**：删除 ≠ 安全，**第一动作永远是轮换 / 吊销密钥**，清历史只是止血。

## 五大类（速查）

| # | 类别 | 典型命中 | 默认级别 |
|---|---|---|---|
| 1 | **凭证与密钥** | 私钥块、AWS `AKIA`/阿里云 `LTAI`、`ghp_` PAT、Slack/Google/Stripe key、连接串里的 `://user:pass@`、JWT/Bearer、通用高熵密钥 | 🔴/🟡 |
| 2 | **个人身份信息(PII)** | 身份证(校验码)、银行卡(Luhn)、手机号、内部邮箱 | 🔴/🟡/🟢 |
| 3 | **基础设施与内网** | 内网 IP(10./172.16-31./192.168.)、`.corp/.internal/.local` 主机名、MAC、内部网关 | 🟡/🟢 |
| 4 | **环境上下文/元数据** | 本地用户名路径(`/Users/张三/`)、SMB/共享路径、内部镜像仓库、暴露业务含义的敏感注释 | 🟡/🟢 |
| 5 | **敏感文件名/类型** | `.env*`(放过 `.example`)、`*.pem/.p12/.keystore/.jks`、`id_rsa`、含 `secret/credential` 的配置文件 | 🔴/🟡 |

> 完整规则清单、白名单哲学、**按类修复指引**见 `references/patterns.md`——动手修之前先读它。

## 强制流程

### 1. 圈定范围（mode 四选一）

- **`all`（默认）** —— 工作区 + 全量 git 历史，开源 / 交付 / 首次自查用这个。
- **`worktree`** —— 只扫当前文件（含被 `.gitignore` 忽略的 `.env`、私钥——这些恰恰最该查）。
- **`history`** —— 只扫 git 历史（怀疑「以前提交过、后来删了」）。按 blob 去重、定位涉及提交。
- **`staged`** —— 只扫本次将提交的暂存内容（pre-commit 钩子用）。

### 2. 跑检测引擎

引擎是 `scripts/scan.py`（纯 Python；有 `rg` 时自动用它加速文件预筛，无则全量遍历——结果一致只是更慢）。Claude Code 下绝对寻址用 `${CLAUDE_PLUGIN_ROOT}/skills/privacy-guard/scripts/scan.py`；Codex / 其他工具用技能目录内的 `scripts/scan.py`。

```bash
# 扫当前项目（工作区+历史），报告写到 .tmp/（不入库）
python <脚本路径> --mode all --path . --out .tmp/privacy-scan
```

- 报告默认同时出 `.md`（人看）和 `.json`（程序 / 复核用）；不带 `--out` 则打到 stdout。
- 退出码：**2=有 critical，1=有 major，0=干净**——可据此在 CI / 钩子里拦截。
- **大库 / 历史很长**时跑得久属正常（要逐 blob 解内容）；只想快速过一遍可先 `--mode worktree`。

### 3. 读报告并核实

- 报告已**分级 + 打码**。对 🔴 critical 项，到「位置」列指出的 `file:line`（或 `[history] path @ commit`）**亲自核对明文**，确认是真密钥还是测试 / 占位（脚本已尽量过滤 `example/test/your_xxx`，但仍可能有漏网误报）。
- 核实时**不要把明文复制进对话或报告**——指出位置即可。

### 4. 按类给修复指引（不替用户执行破坏性操作）

照 `references/patterns.md` 的「按类修复」给出建议。两条最重要：

- **工作区里的密钥**：移到环境变量 / 密钥管理（Vault/KMS/CI secrets），代码里只留引用；把文件名加进 `.gitignore`；补一份 `.env.example` 占位。
- **已进 git 历史 / 推过远端的密钥**：
  1. **先轮换 / 吊销**那把密钥（第一优先级，删历史救不了已泄露的旧值）；
  2. 再用 `git filter-repo`（或 BFG）从历史清除——这会**改写历史**，需 force-push、团队重新 clone，**指引用户自己评估后执行，本技能不代跑**；
  3. 远端平台（GitHub/GitLab）的缓存 / fork / PR 可能仍留有旧值，提醒一并处理。

### 5.（可选）安装 pre-commit 拦截钩子

用户**明确要**「提交前自动拦截」时，才装钩子。钩子自包含：把 `scan.py` 和 `assets/pre-commit` **一起**拷进 `.git/hooks/`，钩子调用它的同目录副本，不依赖外部路径。钩子对**暂存内容**跑 `--mode staged`，命中 critical 时**退出码非 0 挡下提交**。

```bash
cp <技能目录>/scripts/scan.py    .git/hooks/privacy_scan.py
cp <技能目录>/assets/pre-commit  .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit          # Windows 非 WSL 下 git 仍会执行，无需 chmod
```

装前向用户说明：钩子只挡新提交，**挡不住已经在历史里的旧泄露**（那要走第 4 步）；且本地钩子可被 `--no-verify` 绕过，团队级强约束需配 CI 扫描。

## 误报与白名单

- 已内置抑制：`example/sample/dummy/your_xxx/changeme/<...>` 占位、AWS 文档示例 key、Luhn/身份证校验不过的数字串、`.env.example`、`noreply@`/`example.com` 邮箱、回环地址、CI 通用用户名（runner/root…）。
- 仍误报时：**不要为压数字去删规则**——在报告里标注「确认误报」并说明原因即可；要长期豁免某条，建议在 `references/patterns.md` 记录约定，而非偷偷放宽检测。

## 红线

把明文密钥写进对话或入库报告（报告本身泄密）· 把扫描报告 `git add` 入库（应留 `.tmp/`）· 擅自 `git filter-repo`/`rebase`/force-push/删文件/改业务代码（破坏检测-修复分离，且不可逆）· 替用户轮换 / 吊销密钥（牵动线上，须用户亲自来）· 漏掉 `.env`/私钥这类「靠文件名定罪」项 · 拿 `example/test` 占位当真泄露刷数量 · 发现 🔴 凭证泄露却不把「先轮换密钥」摆在第一位。
