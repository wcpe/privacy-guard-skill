# 检测规则清单 · 白名单哲学 · 按类修复指引

> 本文件是 `privacy-guard` 的「为什么这么判 + 命中后怎么修」详表。`scripts/scan.py` 是规则的**唯一真源**，本文随它解释意图。动手修复前先读对应类的「修复」段。

## 目录
- [一、检测规则与严重级](#一检测规则与严重级)
- [二、白名单 / 误报抑制哲学](#二白名单--误报抑制哲学)
- [三、按类修复指引](#三按类修复指引)
- [四、git 历史清除（高危·只给指引）](#四git-历史清除高危只给指引)

---

## 一、检测规则与严重级

严重级三档：🔴 **critical**（几乎必是真泄露 / 后果严重，必须处理）· 🟡 **major**（疑似，需核实）· 🟢 **minor**（上下文 / 元数据，低风险提示）。

### 类别 1 · 凭证与密钥（最高风险）
| 规则 id | 命中 | 级别 | 说明 |
|---|---|---|---|
| `private-key-block` | `-----BEGIN ... PRIVATE KEY-----` | 🔴 | RSA/EC/DSA/OpenSSH/PGP/加密私钥；注释里粘一段也拦 |
| `aws-access-key-id` | `AKIA/ASIA/AROA...` + 16 位 | 🔴 | AWS 访问密钥 ID |
| `aliyun-access-key` | `LTAI` + 12-22 位 | 🔴 | 阿里云 AccessKey ID |
| `github-token` | `ghp_/gho_/ghs_...`、`github_pat_` | 🔴 | GitHub PAT |
| `slack-token` | `xoxb-/xoxp-...` | 🔴 | Slack token |
| `google-api-key` | `AIza` + 35 位 | 🔴 | Google API key |
| `gcp-service-account` | `"type":"service_account"` | 🔴 | GCP 服务账号 JSON 特征 |
| `stripe-secret-key` | `sk_live_/rk_live_...` | 🔴 | Stripe 密钥 |
| `db-uri-password` | `mysql://user:pass@host` | 🔴 | 连接串里的明文口令（取 password 段打码） |
| `jwt-token` | `eyJ....eyJ....sig` | 🟡 | JWT；即便过期也可能泄露内网 / 算法信息 |
| `bearer-token` | `Bearer xxxxx` | 🟡 | Authorization 头里的令牌 |
| `generic-secret-assign` | `*secret*/*token*/*password*/*key* = <高熵值>` | 🟡 | 正则兜不住的通用密钥，靠**香农熵 ≥3.5 + 长度 ≥20 + 字符种类 ≥2** 判定，弥补规则盲区 |

### 类别 2 · 个人身份信息（PII，合规红线）
| 规则 id | 命中 | 级别 | 说明 |
|---|---|---|---|
| `cn-id-card` | 18 位身份证 | 🔴 | **ISO 7064 mod 11-2 校验码 + 出生年校验**，几乎无误报 |
| `bank-card` | 13-19 位 | 🔴 | **Luhn 校验**过才报，过滤普通长数字 |
| `cn-mobile` | 中国大陆 11 位手机号 | 🟡 | `1[3-9]` 开头，前后非数字边界 |
| `email` | 邮箱地址 | 🟢 | 放过 `noreply@`/`example.com`/`user@`；内部带姓名 / 工号邮箱值得关注 |

### 类别 3 · 基础设施与内网架构
| 规则 id | 命中 | 级别 | 说明 |
|---|---|---|---|
| `private-ipv4` | `10./172.16-31./192.168.` | 🟢 | 内网拓扑；放过 `10.0.0.0`/`192.168.0.0` 网段地址 |
| `internal-hostname` | `*.corp/.internal/.intra/.lan/.local` | 🟡 | 内网域名 / 主机名 |
| `mac-address` | `xx:xx:xx:xx:xx:xx` | 🟢 | 物理网卡地址；放过全 0 / 广播 |

### 类别 4 · 环境上下文与元数据（AI 最爱带进来的）
| 规则 id | 命中 | 级别 | 说明 |
|---|---|---|---|
| `local-user-path` | `/Users/张三/`、`C:\Users\lisi\` | 🟢 | 路径里的开发者真名；放过 runner/root/admin 等通用名 |
| `smb-share-path` | `smb://...`、`\\host\share` | 🟡 | 内部文件共享路径 |
| `sensitive-comment` | 注释含「明文 / 盐值 / 身份证号 / plaintext password」 | 🟢 | 字段名 `id_card`/`salt`/`pwd` 本身安全，危险的是泄露业务含义的注释 |

> 内部镜像仓库（`harbor.内网域/...`）通常会被 `internal-hostname` / `private-ipv4` 命中；若用公网域名托管内部镜像，按需在项目里加自定义规则。

### 类别 5 · 敏感文件名 / 类型（按文件名定罪，与内容无关）
| 规则 id | 命中文件名 | 级别 | 说明 |
|---|---|---|---|
| `dotenv-file` | `.env`、`.env.production`… | 🔴 | **放过** `.env.example/.sample/.template/.dist` |
| `key-cert-file` | `*.pem/.p12/.pfx/.key/.keystore/.jks/.ppk/.kdbx/.ovpn/.asc` | 🔴 | 私钥 / 证书 / 密钥库 |
| `ssh-key-file` | `id_rsa/id_dsa/id_ecdsa/id_ed25519` | 🔴 | SSH 私钥 |
| `token-config-file` | `.npmrc/.pypirc/.netrc/.dockercfg` | 🟡 | 常含仓库 / 注册表令牌 |
| `secret-named-file` | `secret*.json`、`credentials.xml`… | 🟡 | 文件名含 `secret/private/credential` 的配置（即便内容像乱码） |

---

## 二、白名单 / 误报抑制哲学

**目标不是「零误报」，而是「真泄露不被噪声淹没」。** 已内置的抑制：

- **占位 / 示例值**：`your_xxx/example/sample/dummy/placeholder/changeme/<...>/xxxx/test_key`、AWS 文档样例 `AKIAIOSFODNN7EXAMPLE`。
- **数值校验**：身份证走校验码、银行卡走 Luhn——不过校验的长数字不报。
- **高熵门槛**：通用密钥要熵 ≥3.5 且字符够杂，挡掉 `password = "0000000000000000"` 这类。
- **文件名豁免**：`.env.example` 一族、`secret.example.json`。
- **通用值豁免**：`noreply@/example.com` 邮箱、回环 / 网段基址、CI 通用用户名（runner/root/ubuntu…）。

**仍误报怎么办**：在报告里标「确认误报 + 原因」，**不要为了好看去删 / 放宽规则**——今天压掉的噪声，明天可能正好漏掉真东西。要长期豁免某模式，把约定写进本文件备查，而非偷偷改检测。

---

## 三、按类修复指引

通用第一步：**判断它有没有进过 git 历史 / 推过远端**。进过 → 一律当「已泄露」，**先轮换密钥**再谈清理（见第四节）。只在工作区、从未提交 → 直接改代码即可。

- **类别 1 凭证与密钥**：
  - 从代码挪出——读环境变量 / 密钥管理（Vault、云 KMS、CI/CD secrets），源码只留 `os.environ["X"]` 这类引用。
  - 把对应文件加进 `.gitignore`，补一份 `*.example` 占位供他人填。
  - **已泄露的密钥立即在签发方轮换 / 吊销**（AWS IAM、GitHub Settings→Tokens、数据库改密…），这是止损第一步。
- **类别 2 PII**：生产数据不进仓库；测试 / 种子数据用**合成假数据**（faker 之类）。日志 / 注释里的真实 PII 一并清除。涉合规（GDPR / 个保法）的，按公司流程上报。
- **类别 3 内网架构**：内网 IP / 主机名 / 网关换成配置项或占位（`db.internal.example`），别把真实拓扑刻进代码。示例文档用文档保留地址段（`192.0.2.0/24`、`example.com`）。
- **类别 4 环境元数据**：清掉路径里的真名（用 `~`/`$HOME`/相对路径）、内部共享与镜像仓库地址；删掉泄露业务敏感含义的注释。
- **类别 5 敏感文件**：不应入库的密钥 / 证书 / `.env` 从仓库移除并加 `.gitignore`；若已提交，按第四节清历史 + 轮换。

---

## 四、git 历史清除（高危 · 只给指引，本技能不代跑）

一旦敏感数据进过历史，**删当前文件没用**——旧 commit 里仍在。处理顺序：

1. **先轮换 / 吊销密钥**。历史可能已被 clone / fork / 被远端缓存，**必须假设旧值已外泄**，改写历史只是收尾。
2. **改写历史**（二选一，都需 force-push、团队重新 clone，**让用户评估后亲自执行**）：
   - `git filter-repo --path <文件> --invert-paths`（推荐，比 filter-branch 快且安全）；或按内容 `--replace-text`。
   - BFG：`bfg --delete-files <文件>` 或 `--replace-text passwords.txt`。
3. `git push --force`（或 `--force-with-lease`）到所有远端；通知协作者**重新 clone / rebase**，旧克隆里仍含泄露。
4. **清远端残留**：GitHub/GitLab 的旧 PR、fork、缓存快照可能仍存旧值——联系平台或删除相关引用。

> 本技能**只给到这里**：上面每条都不可逆且影响团队，必须由用户知情后自己跑。技能绝不自动 `filter-repo`/force-push/吊销密钥。
