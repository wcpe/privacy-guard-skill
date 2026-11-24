# Privacy Guard

一个「隐私 / 敏感数据检测」AI 编码技能：扫描**当前项目工作区**与 **git 全量历史**，找出被硬编码进去的敏感数据，按**五大类**分级、**脱敏**报告，并给出**按类修复指引**。同一套 `SKILL.md` 通用于 **Claude Code / Devin / OpenAI Codex**（插件一键装）与任何只认技能目录的 agent（opencode、Cursor、Gemini CLI 等，拷目录即用）。在 [sdd-skills](https://github.com/wcpe/sdd-skills) 项目里，验收 / 发版 / 审查 / 改造技能会自动接入它。

**只检测、只报告、给指引——绝不替你改写 git 历史、force-push 或吊销密钥**（这些不可逆、牵动远端与团队的操作，交由你知情后亲自执行）。

## 它查什么（五大类）

| # | 类别 | 典型命中 |
|---|---|---|
| 1 | **凭证与密钥** | 私钥块、AWS `AKIA`/阿里云 `LTAI`、`ghp_` PAT、Slack/Google/Stripe key、连接串里的 `://user:pass@`、JWT/Bearer、通用高熵密钥（熵值检测） |
| 2 | **个人身份信息(PII)** | 身份证（校验码）、银行卡（Luhn）、手机号、内部邮箱 |
| 3 | **基础设施与内网** | 内网 IP（10./172.16-31./192.168.）、`.corp/.internal/.local` 主机名、MAC |
| 4 | **环境上下文/元数据** | 本地用户名路径（`/Users/张三/`）、SMB/共享路径、暴露业务含义的敏感注释 |
| 5 | **敏感文件名/类型** | `.env*`（放过 `.example`）、`*.pem/.p12/.keystore`、`id_rsa`、含 `secret/credential` 的配置文件 |

检测引擎 `skills/privacy-guard/scripts/scan.py`：**rg + Python**——有 ripgrep 时用它加速文件预筛，再用 Python 做精确分类与**熵值 / Luhn / 身份证校验 / 白名单**降误报；无 rg 时全量遍历，结果一致。报告里命中片段一律**打码**，绝不落明文。

## 能力一览

- **五种范围**：`worktree` / `history` / `staged` / `all`，以及 `--since <ref>` 只扫区间新增（PR 门、发版门）。
- **项目配置** `.privacy-guard.json`：按规则 / 路径 / 指纹豁免（必须写理由）、行内 `privacy-guard:allow`、改级别或关规则、加自定义规则、设 `fail_on` 门槛。
- **基线**：老项目 `--write-baseline` 先记账已有命中，之后只拦新增；基线只存指纹与打码片段，可入库。
- **输出**：Markdown / JSON / SARIF（GitHub Code Scanning），退出码 2=critical、1=达到门槛、0=通过、3=配置错误。
- **拦截**：Claude / Devin / Codex 会话内提交门 hook；`install_hook.py` 一键装 git 钩子（识别 husky / core.hooksPath）；pre-commit 框架；GitHub Actions 模板。

## 怎么用

技能触发后会：圈定范围（工作区 / 历史 / 暂存 / 全部）→ 跑 `scan.py` 出脱敏分级报告到 `.tmp/`（不入库）→ 对 🔴 项指出位置供你核实 → 按类给修复建议 → （你明确要时）装可选的 pre-commit 拦截钩子。

直接跑引擎也行：

```bash
python skills/privacy-guard/scripts/scan.py --mode all --path . --out .tmp/privacy-scan
python skills/privacy-guard/scripts/scan.py --since v1.2.0 --fail-on critical      # 只看上个版本以来新增
python skills/privacy-guard/scripts/scan.py --mode all --write-baseline .privacy-guard-baseline.json  # 老项目记基线
python skills/privacy-guard/scripts/scan.py --mode worktree --format sarif --out .tmp/privacy        # 给 Code Scanning
```

配置格式、基线与豁免规则见 `skills/privacy-guard/SKILL.md`「项目配置与基线」。

### 接入 pre-commit 框架 / CI

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/wcpe/privacy-guard-skill
    rev: v0.4.0        # 或某个提交 SHA
    hooks:
      - id: privacy-guard
```

GitHub Actions：把 `skills/privacy-guard/assets/ci/github-actions.yml` 拷到 `.github/workflows/privacy-scan.yml`。

## 插件增强（Claude Code / Devin / Codex）

除技能外，给 **Claude Code** 捆绑三类组件（仅 CC 生效；引擎仍是同一个 `scan.py`，Codex/opencode 照常用技能）：

- **提交门护栏 hook** `hooks/`：在 Claude 会话里 `git commit` 时，自动对**暂存内容**跑 `scan.py --mode staged`——命中 🔴critical 即**阻断提交**并列打码位置；🟡major 警告不挡。比手动装 git 钩子省事（任意项目即时生效；缺 python 时优雅降级、不挡正常提交）。
- **斜杠命令** `commands/`（仅 Claude Code）：`/privacy-scan`（工作区+历史）、`/privacy-scan-staged`、`/privacy-scan-history`、`/privacy-scan-range <ref>`、`/privacy-install-hook`。
- **MCP 工具** `mcp/`：`privacy_scan(path, mode, since, fail_on, no_baseline)`——复用 `scan.py` 返回结构化（已打码）findings 与是否通过门槛。

> Node 胶水只在真要扫时才拉起 `python scan.py`：引擎零改动，复用现成的 rg 预筛 + 熵值/Luhn/身份证校验/白名单。

## 安装

同一套 `skills/`，三种工具都能用。仓库地址：`https://github.com/wcpe/privacy-guard-skill`。

### Claude Code（插件）

本插件经 **wcpe 组织市场**（[wcpe/claude-plugins](https://github.com/wcpe/claude-plugins)）分发，装后默认 **User 作用域**（所有项目可用）：

```
/plugin marketplace add wcpe/claude-plugins        # wcpe 组织市场（含 privacy-guard 等）
/plugin install privacy-guard@wcpe                  # 格式：<插件名>@<市场名>
/plugin marketplace update wcpe                     # 以后更新到最新
```

CLI 等价：`claude plugin marketplace add wcpe/claude-plugins` / `claude plugin install privacy-guard@wcpe`。

### Devin（插件）

在 Devin 的插件设置里从 GitHub 安装 `https://github.com/wcpe/privacy-guard-skill/tree/master`（个人或组织范围均可；只填仓库地址可能停在旧提交），或在 Devin CLI 里 `devin plugins install wcpe/privacy-guard-skill`。装好后对新会话生效：

- 技能以 `/privacy-guard:privacy-guard [worktree|staged|history|all] [项目路径]` 调用；Claude 的 `commands/` 斜杠命令在 Devin 下不加载，用技能参数代替。
- 清单 `.devin-plugin/plugin.json` 内联声明 MCP `privacy_scan`（Devin 下以插件目录为工作目录启动，因此调用时请传 `path`）；根目录 `hooks.json` 是 Devin 提交门，匹配 `exec` 工具里的 `git commit`，按 `DEVIN_PLUGIN_ROOT` 定位插件、自己查找 node 与 python。
- Devin 会按 Claude 兼容顺带读 `hooks/hooks.json`，启动器 `hooks/run-hook.sh` 在 Devin 下自动跳过它，提交门不会跑两遍。

### OpenAI Codex

`.codex-plugin/plugin.json` 声明了技能、MCP（`.codex-mcp.json`，以插件根为工作目录）和提交门 hook（复用 `hooks/hooks.json`，匹配 `Bash`；拦截时同时输出 `permissionDecision: deny`）。Codex 插件形式尚未在真实 Codex 中验证；只要技能的话，按目录安装最稳：

```
git clone https://github.com/wcpe/privacy-guard-skill
cp -r privacy-guard-skill/skills/* ~/.codex/skills/     # 全局：所有项目可用
# 或仅当前项目：拷进 <项目>/.codex/skills/
```

本仓库也带 `.codex-plugin/plugin.json`（`skills` 指向 `./skills/`），若你的 Codex 版本支持插件系统，可按其插件流程安装；以目录安装为准。

### opencode

opencode 原生认 `SKILL.md`（并兼容 `.claude/skills/`），靠目录发现：

```
git clone https://github.com/wcpe/privacy-guard-skill
cp -r privacy-guard-skill/skills/* ~/.config/opencode/skills/   # 全局
# 或仅当前项目：拷进 <项目>/.opencode/skills/（或 .claude/skills/）
```

### 其他只认技能的 agent

| agent | 全局目录 | 项目目录 |
|---|---|---|
| Claude Code（不装插件） | `~/.claude/skills/` | `<项目>/.claude/skills/` |
| Cursor | `~/.cursor/skills/` | `<项目>/.cursor/skills/` |
| Gemini CLI | `~/.gemini/skills/` | `<项目>/.gemini/skills/` |
| 通用约定 | `~/.agents/skills/` | `<项目>/.agents/skills/` |

拷 `skills/privacy-guard` 整个目录即可；具体目录以各 agent 当前文档为准。纯技能方式下没有会话内提交门与 MCP，用 `install_hook.py` 装 git 钩子补上拦截。

> Windows 用 `Copy-Item privacy-guard-skill\skills\* <目标> -Recurse`。技能自带的 `scripts/` 与 `assets/` 随技能目录一起拷贝。

## 仓库结构

```
privacy-guard-skill/                 ← 仓库根 = 插件本体（分发经 wcpe 组织市场 wcpe/claude-plugins）
├── .claude-plugin/plugin.json       Claude Code 插件清单
├── .codex-plugin/plugin.json        Codex 插件清单（技能 + .codex-mcp.json + hooks/hooks.json）
├── .codex-mcp.json                  Codex 的 MCP 注册
├── .pre-commit-hooks.yaml           pre-commit 框架 hook 定义
├── .privacy-guard.json              本仓库自身的扫描配置（规则文档 / 测试夹具豁免）
├── .devin-plugin/plugin.json        Devin 插件清单（内联 MCP；hook 见根目录 hooks.json）
├── .mcp.json                        MCP server 注册（Claude Code）
├── hooks.json                       Devin 提交门 hook（匹配 exec）
├── hooks/                           提交门护栏（Node 胶水 → scan.py）
│   ├── hooks.json                   Claude Code 提交门 hook（匹配 Bash）
│   ├── run-hook.sh                  跨宿主启动器：自找 node，Devin 下跳过 Claude 配置
│   ├── find-python.cjs              hook 与 MCP 共用的 python 查找
│   └── guard-commit.js
├── tests/                           hook / MCP 行为测试（node --test tests/）
├── commands/                        斜杠命令 /privacy-scan* 与 /privacy-install-hook
├── mcp/privacy-mcp.mjs              MCP：privacy_scan(path, mode)
└── skills/
    └── privacy-guard/
        ├── SKILL.md                 工作流：圈范围 → 扫描 → 核实 → 修复指引 → 可选钩子
        ├── scripts/scan.py          检测引擎（rg+py，worktree/history/staged/range/all，配置 / 基线 / SARIF）
        ├── scripts/install_hook.py  git pre-commit 钩子安装器
        ├── references/patterns.md   5 类规则 · 白名单哲学 · 按类修复 · 历史清除指引
        ├── assets/pre-commit        可选 git 提交前拦截钩子（自包含）
        └── assets/ci/               GitHub Actions 扫描模板（SARIF）
```

## 边界与免责

- **不**自动改写 git 历史 / force-push / 删文件 / 改业务代码 / 轮换密钥——只给指引，你自己评估后执行。
- 报告留 `.tmp/`，**不要入库**（它含敏感数据位置）。
- 检测有边界：正则 + 熵值挡不住一切，仍可能漏 / 误报；它是**自查辅助**，不替代专业密钥扫描服务与安全评审。
