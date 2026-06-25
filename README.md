# Privacy Guard

一个「隐私 / 敏感数据检测」AI 编码技能：扫描**当前项目工作区**与 **git 全量历史**，找出被硬编码进去的敏感数据，按**五大类**分级、**脱敏**报告，并给出**按类修复指引**。同一套 `SKILL.md` 通用于 **Claude Code**（插件一键装）、**OpenAI Codex** 与 **opencode**。

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

## 怎么用

技能触发后会：圈定范围（工作区 / 历史 / 暂存 / 全部）→ 跑 `scan.py` 出脱敏分级报告到 `.tmp/`（不入库）→ 对 🔴 项指出位置供你核实 → 按类给修复建议 → （你明确要时）装可选的 pre-commit 拦截钩子。

直接跑引擎也行：

```bash
python skills/privacy-guard/scripts/scan.py --mode all --path . --out .tmp/privacy-scan
# 退出码：2=有 critical，1=有 major，0=干净（便于接进 CI / 钩子）
```

## 安装

同一套 `skills/`，三种工具都能用。仓库地址：`https://github.com/wcpe/privacy-guard-skill`。

### Claude Code（插件）

本仓库自身即 marketplace，装后默认 **User 作用域**（所有项目可用）：

```
/plugin marketplace add wcpe/privacy-guard-skill   # git 地址或本地路径均可
/plugin install privacy-guard@privacy-guard        # 格式：<插件名>@<市场名>
/plugin marketplace update privacy-guard           # 以后更新到最新
```

CLI 等价：`claude plugin marketplace add wcpe/privacy-guard-skill` / `claude plugin install privacy-guard@privacy-guard`。

### OpenAI Codex

Codex 原生认 `SKILL.md`。最稳的装法是把技能放进 Codex 的技能目录（无需清单）：

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

> Windows 用 `Copy-Item privacy-guard-skill\skills\* <目标> -Recurse`。技能自带的 `scripts/` 与 `assets/` 随技能目录一起拷贝。

## 仓库结构

```
privacy-guard-skill/                 ← 仓库根 = 插件 = marketplace
├── .claude-plugin/                  Claude Code 插件清单
│   ├── plugin.json
│   └── marketplace.json             市场清单（source: "./"）
├── .codex-plugin/                   Codex 插件清单
│   └── plugin.json                  skills 指向 ./skills/
└── skills/
    └── privacy-guard/
        ├── SKILL.md                 工作流：圈范围 → 扫描 → 核实 → 修复指引 → 可选钩子
        ├── scripts/
        │   └── scan.py              检测引擎（rg+py，worktree/history/staged/all）
        ├── references/
        │   └── patterns.md          5 类规则清单 · 白名单哲学 · 按类修复 · 历史清除指引
        └── assets/
            └── pre-commit           可选提交前拦截钩子（自包含）
```

## 边界与免责

- **不**自动改写 git 历史 / force-push / 删文件 / 改业务代码 / 轮换密钥——只给指引，你自己评估后执行。
- 报告留 `.tmp/`，**不要入库**（它含敏感数据位置）。
- 检测有边界：正则 + 熵值挡不住一切，仍可能漏 / 误报；它是**自查辅助**，不替代专业密钥扫描服务与安全评审。
