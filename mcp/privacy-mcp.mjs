#!/usr/bin/env node
// 最小零依赖 MCP stdio server（JSON-RPC 2.0，换行分隔）：隐私/敏感数据扫描。
// 工具 privacy_scan：复用 Python 引擎 scan.py，返回**脱敏**的分级结果（counts + findings）。只读。
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { createRequire } from 'node:module'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCAN = join(HERE, '..', 'skills', 'privacy-guard', 'scripts', 'scan.py')
const { findPython } = createRequire(import.meta.url)('../hooks/find-python.cjs')
const PLUGIN_ROOT = resolve(HERE, '..')
const SERVER = { name: 'privacy-guard', version: '0.4.1' }

const TOOLS = [
  {
    name: 'privacy_scan',
    description:
      '扫描项目里硬编码的隐私/敏感数据（凭证密钥/PII/内网/元数据/敏感文件），返回**已打码**的分级结果（counts + findings + 结论）。复用 Python 引擎 scan.py（rg 预筛 + 熵值/Luhn/身份证校验/白名单）。只检测、只读，不改任何文件、不动 git 历史。',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: '要扫描的项目根目录，建议传绝对路径（Devin 下 MCP 进程的工作目录是插件目录，不传会报错提示）' },
        mode: {
          type: 'string',
          enum: ['worktree', 'history', 'staged', 'range', 'all'],
          description: '范围：worktree=当前文件(默认,最快) / history=git 全量历史(可能慢) / staged=暂存区 / range=since..HEAD 的新增内容(PR / 版本门) / all=工作区+历史'
        },
        since: { type: 'string', description: 'range 模式起点：tag / 分支 / 提交（如上个发布 tag、PR 的 base 分支）。给了 since 且未给 mode 时自动用 range' },
        fail_on: { type: 'string', enum: ['critical', 'major', 'minor', 'never'], description: '从哪一级起判为不通过（默认取项目 .privacy-guard.json 的 fail_on，否则 major）' },
        no_baseline: { type: 'boolean', description: '忽略项目基线，报出全部命中（默认按 .privacy-guard.json 的 baseline 接纳已知项）' }
      }
    }
  }
]

function send (m) { process.stdout.write(JSON.stringify(m) + '\n') }
function ok (id, r) { send({ jsonrpc: '2.0', id, result: r }) }
function err (id, c, m) { send({ jsonrpc: '2.0', id, error: { code: c, message: m } }) }
function text (t, isError = false) { return { content: [{ type: 'text', text: t }], isError } }

function privacyScan (args) {
  const py = findPython()
  if (!py) return text('未找到可用的 python——扫描引擎 scan.py 依赖 python，请先安装。', true)
  // Devin 下 MCP 进程的 cwd 是插件目录而不是用户项目：没传 path 时用宿主给的项目根，仍落在插件目录就要求显式传
  // 相对 path 也以项目根为基准解析，而不是 MCP 进程 cwd
  const project = process.env.DEVIN_PROJECT_DIR || process.env.CLAUDE_PROJECT_DIR || process.cwd()
  const dir = resolve(project, args.path || '.')
  if (dir === PLUGIN_ROOT && !(args.path && isAbsolute(args.path))) return text('请用 path 参数传入要扫描的项目根目录（绝对路径）：当前工作目录是插件自身目录，不是你的项目。', true)
  const mode = args.mode || (args.since ? 'range' : 'worktree')
  const argv = [SCAN, '--mode', mode, '--path', dir, '--format', 'json']
  if (args.since) argv.push('--since', String(args.since))
  if (args.fail_on) argv.push('--fail-on', String(args.fail_on))
  if (args.no_baseline) argv.push('--no-baseline')
  const r = spawnSync(py, argv, { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  if (r.error) return text('引擎执行失败：' + r.error.message, true)
  if (r.status === 3) return text((r.stderr || '').trim() || '扫描参数或项目配置有误', true)
  let data
  try { data = JSON.parse(r.stdout || '{}') } catch (e) { return text('引擎输出解析失败：\n' + (r.stdout || r.stderr || '').slice(0, 2000), true) }
  const c = data.counts || {}
  const c0 = data.counts || {}
  const verdict = (c0.critical ? '🔴 发现致命泄露(critical)' : c0.major ? '🟡 发现疑似泄露(major)' : '✅ 未发现致命/疑似泄露') + (r.status === 0 ? '，门槛通过' : '，门槛不通过')
  const sup = data.suppressed || {}
  const head = `隐私扫描（${dir}，${data.scope || mode}）：${verdict}\n统计：🔴 ${c.critical || 0} · 🟡 ${c.major || 0} · 🟢 ${c.minor || 0}（退出码 ${r.status}，门槛 fail_on=${data.fail_on}：2=critical/1=达到门槛/0=通过）\n已豁免：行内 ${sup.inline || 0} · 配置 ${sup.config || 0} · 基线 ${sup.baseline || 0}\n所有片段已打码；明文请到对应位置核对。\n`
  return text(head + '\n' + JSON.stringify({ scope: data.scope, counts: c, suppressed: sup, passed: r.status === 0, findings: data.findings || [] }, null, 2))
}

function handle (msg) {
  const { id, method, params } = msg
  if (method === 'initialize') {
    return ok(id, { protocolVersion: (params && params.protocolVersion) || '2024-11-05', capabilities: { tools: {} }, serverInfo: SERVER })
  }
  if (method === 'notifications/initialized') return
  if (method === 'tools/list') return ok(id, { tools: TOOLS })
  if (method === 'tools/call') {
    const name = params && params.name
    const a = (params && params.arguments) || {}
    try {
      if (name === 'privacy_scan') return ok(id, privacyScan(a))
      return err(id, -32601, `unknown tool: ${name}`)
    } catch (e) {
      return ok(id, text('工具执行异常：' + e.message, true))
    }
  }
  if (id !== undefined) err(id, -32601, `method not found: ${method}`)
}

let buf = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', (chunk) => {
  buf += chunk
  let i
  while ((i = buf.indexOf('\n')) >= 0) {
    const line = buf.slice(0, i).trim()
    buf = buf.slice(i + 1)
    if (!line) continue
    let msg
    try { msg = JSON.parse(line) } catch (e) { continue }
    handle(msg)
  }
})
