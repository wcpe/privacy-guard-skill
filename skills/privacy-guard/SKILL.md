---
name: privacy-guard
description: 检测当前项目工作区与 git 历史中是否硬编码了隐私/敏感数据(凭证密钥、PII、内网架构、环境元数据、敏感文件)时使用。当用户说"扫一下有没有泄露密钥/隐私、提交前查敏感信息、检查 git 历史有没有密码、有没有硬编码 token/身份证/内网IP、开源/交付前脱敏自查、防止把 .env/私钥提交上去、装个提交前拦截钩子防泄密、secret scanning、敏感信息检测"时触发——即使没明说"隐私扫描"。捆绑 rg+Python 检测引擎(正则+熵值+Luhn/身份证校验+白名单降误报),扫工作区与全量 git 历史,产出**脱敏**分级报告 + 按类修复指引(含历史清除与密钥轮换),可选安装 pre-commit 拦截钩子。**只检测、只报告、给指引——绝不自动改写历史或吊销密钥**。
argument-hint: "[worktree|staged|history|range <ref>|all] [项目路径]"
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

### 0. 定位引擎（任何 agent 通用，不依赖插件）

`scripts/scan.py` 与本 SKILL.md 同目录树：**本文件所在目录 + `/scripts/scan.py`**。纯技能安装（Codex / opencode / Cursor / Gemini CLI 等拷目录的方式）就用这个路径；插件安装下也一样可用（Claude Code 另可写 `${CLAUDE_PLUGIN_ROOT}/skills/privacy-guard/scripts/scan.py`）。若环境里有 MCP 工具 `privacy_scan`，可直接调用它（**务必传 `path` = 项目根**），等价于跑脚本。

### 意图 → 怎么扫（速查）

| 用户说的 | 命令要点 |
|---|---|
| 开源 / 交付前全面自查 | `--mode all` |
| 提交前查一下 | `--mode staged` |
| 以前提交过后来删了 | `--mode history` |
| 这个 PR / 这个版本有没有带进新泄露 | `--since <base 分支或上个 tag>`（range 模式，只看新增） |
| 装提交前拦截 | `scripts/install_hook.py`（第 5 步） |
| 接 CI / GitHub Code Scanning | `--format sarif` + `assets/ci/github-actions.yml`（第 6 步） |
| 老项目一扫一大片、只想管新增 | `--write-baseline`（见「项目配置与基线」） |

### 1. 圈定范围（mode 五选一）

- **`all`（默认）** —— 工作区 + 全量 git 历史，开源 / 交付 / 首次自查用这个。
- **`worktree`** —— 只扫当前文件（含被 `.gitignore` 忽略的 `.env`、私钥——这些恰恰最该查）。
- **`history`** —— 只扫 git 历史（怀疑「以前提交过、后来删了」）。按 blob 去重、定位涉及提交。
- **`staged`** —— 只扫本次将提交的暂存内容（pre-commit 钩子用）。
- **`range`**（`--since <ref>`）—— 只扫 `ref..HEAD` 各提交**新增**的行与文件，结果带提交号。PR 门（ref=base 分支）、发版门（ref=上个 tag）用它；ref 无效时退出码 3，不会静默放行。

### 2. 跑检测引擎

引擎是 `scripts/scan.py`（纯 Python 标准库；有 `rg` 时自动用它加速文件预筛，无则全量遍历——结果一致只是更慢）。路径见第 0 步。

```bash
# 扫当前项目（工作区+历史），报告写到 .tmp/（不入库）
python <脚本路径> --mode all --path . --out .tmp/privacy-scan
```

- 报告默认同时出 `.md`（人看）和 `.json`（程序 / 复核用）；不带 `--out` 则打到 stdout。
- 退出码：**2=有 critical，1=达到 `--fail-on` 门槛（默认 major），0=通过，3=配置或参数错误**——可据此在 CI / 钩子里拦截。`--fail-on critical` 只拦致命项。
- 格式：`--format md|json|both|sarif`；SARIF 可直接上传 GitHub Code Scanning。
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

用户**明确要**「提交前自动拦截」时，才装钩子。用安装脚本（自动识别 `core.hooksPath` / husky、worktree 与子模块；已有别人的 pre-commit 时不覆盖，改写 `pre-commit.privacy-guard` 并告诉你怎么串联）：

```bash
python <技能目录>/scripts/install_hook.py --path .
```

钩子自包含（引擎副本 `privacy_scan.py` + `pre-commit`），对**暂存内容**跑 `--mode staged`、读项目 `.privacy-guard.json` 与基线，命中 critical 时挡下提交。用 [pre-commit](https://pre-commit.com) 框架的项目也可以在 `.pre-commit-config.yaml` 里引用本仓库的 `privacy-guard` hook（见 README）。

装前向用户说明：钩子只挡新提交，**挡不住已经在历史里的旧泄露**（那要走第 4 步）；且本地钩子可被 `--no-verify` 绕过，团队级强约束需配 CI 扫描。

### 6.（可选）接入 CI

把 `assets/ci/github-actions.yml` 拷到 `.github/workflows/privacy-scan.yml`：PR 上扫 `base..head` 新增，推主线扫工作区，SARIF 上传 Code Scanning，critical 判失败。其他 CI 照抄其中两条 `scan.py` 命令即可。

## 项目配置与基线

项目根放 `.privacy-guard.json`（可入库；钩子、MCP、CI 都会读）：

```json
{
  "fail_on": "major",
  "baseline": ".privacy-guard-baseline.json",
  "ignore_paths": ["testdata/**"],
  "allow": [
    { "rule": "email", "path": "docs/**", "reason": "文档里的公开联系邮箱" },
    { "fingerprint": "3f9c0a1b2c3d4e5f", "reason": "已确认是测试夹具里的假 key" }
  ],
  "severity": { "private-ipv4": "off", "internal-hostname": "minor" },
  "rules": [{ "id": "corp-api-key", "pattern": "CORP-[A-Z0-9]{24}", "severity": "critical" }]
}
```

- `allow` 每条**必须写 `reason`**，按 rule / path（glob）/ fingerprint 任意组合匹配；指纹在 JSON 报告里，不含明文。
- 行内豁免：在该行写 `privacy-guard:allow`（整行）或 `privacy-guard:allow rule-a,rule-b`。
- **基线**：老项目先 `--write-baseline .privacy-guard-baseline.json` 把现存命中记账（只存指纹、规则与路径，不存片段），之后只有新增泄露才判失败；`--no-baseline` 随时看全量。**公开仓库别提交含手机号、身份证等个人信息命中的基线**（取值范围小，可由指纹穷举还原）。**进基线 ≠ 安全**：基线里的凭证仍要按第 4 步轮换，处理完从基线删掉。
- 所有豁免都会在报告里计数（行内 / 配置 / 基线），不会悄悄发生。

## 在 SDD 项目里

装了 sdd-skills 时，它的验收（`sdd-accept-phase`）、发版（`sdd-release-version`）、代码审查（`sdd-review-code`）、改造（`retrofit-to-sdd`）会在关键节点调用本技能：发版 / 验收门用 `--since <上个 tag>` 只看本版新增，retrofit 时生成基线。本技能本身不要求 SDD。

## 误报与白名单

- 已内置抑制：`example/sample/dummy/your_xxx/changeme/<...>` 占位、AWS 文档示例 key、Luhn/身份证校验不过的数字串、`.env.example`、`noreply@`/`example.com` 邮箱、回环地址、CI 通用用户名（runner/root…）。
- 仍误报时：**不要为压数字去删规则**——用 `.privacy-guard.json` 的 `allow`（写清 reason）或行内 `privacy-guard:allow` 精确豁免，而不是放宽检测。

## 红线

把明文密钥写进对话或入库报告（报告本身泄密）· 把扫描报告 `git add` 入库（应留 `.tmp/`）· 擅自 `git filter-repo`/`rebase`/force-push/删文件/改业务代码（破坏检测-修复分离，且不可逆）· 替用户轮换 / 吊销密钥（牵动线上，须用户亲自来）· 漏掉 `.env`/私钥这类「靠文件名定罪」项 · 拿 `example/test` 占位当真泄露刷数量 · 发现 🔴 凭证泄露却不把「先轮换密钥」摆在第一位。
