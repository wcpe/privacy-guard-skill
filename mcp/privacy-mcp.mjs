#!/usr/bin/env node
// 最小零依赖 MCP stdio server（JSON-RPC 2.0，换行分隔）：隐私/敏感数据扫描。
// 工具 privacy_scan：复用 Python 引擎 scan.py，返回**脱敏**的分级结果（counts + findings）。只读。
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const HERE = dirname(fileURLToPath(import.meta.url))
const SCAN = join(HERE, '..', 'skills', 'privacy-guard', 'scripts', 'scan.py')
const SERVER = { name: 'privacy-guard', version: '0.2.0' }

const TOOLS = [
  {
    name: 'privacy_scan',
    description:
      '扫描项目里硬编码的隐私/敏感数据（凭证密钥/PII/内网/元数据/敏感文件），返回**已打码**的分级结果（counts + findings + 结论）。复用 Python 引擎 scan.py（rg 预筛 + 熵值/Luhn/身份证校验/白名单）。只检测、只读，不改任何文件、不动 git 历史。',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: '项目根目录（默认当前工作目录）' },
        mode: {
          type: 'string',
          enum: ['worktree', 'history', 'staged', 'all'],
          description: '范围：worktree=当前文件(默认,最快) / history=git 全量历史(可能慢) / staged=暂存区 / all=工作区+历史'
        }
      }
    }
  }
]

function send (m) { process.stdout.write(JSON.stringify(m) + '\n') }
function ok (id, r) { send({ jsonrpc: '2.0', id, result: r }) }
function err (id, c, m) { send({ jsonrpc: '2.0', id, error: { code: c, message: m } }) }
function text (t, isError = false) { return { content: [{ type: 'text', text: t }], isError } }

function findPython () {
  for (const c of ['python3', 'python', 'py']) {
    const t = spawnSync(c, ['-c', 'import sys'], { stdio: 'ignore' })
    if (t.status === 0) return c
  }
  return null
}

function privacyScan (args) {
  const py = findPython()
  if (!py) return text('未找到可用的 python——扫描引擎 scan.py 依赖 python，请先安装。', true)
  const dir = args.path || process.cwd()
  const mode = args.mode || 'worktree'
  const r = spawnSync(py, [SCAN, '--mode', mode, '--path', dir, '--format', 'json'], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 })
  if (r.error) return text('引擎执行失败：' + r.error.message, true)
  let data
  try { data = JSON.parse(r.stdout || '{}') } catch (e) { return text('引擎输出解析失败：\n' + (r.stdout || r.stderr || '').slice(0, 2000), true) }
  const c = data.counts || {}
  const verdict = r.status === 2 ? '🔴 发现致命泄露(critical)' : r.status === 1 ? '🟡 发现疑似泄露(major)' : '✅ 未发现致命/疑似泄露'
  const head = `隐私扫描（${dir}，mode=${mode}）：${verdict}\n统计：🔴 ${c.critical || 0} · 🟡 ${c.major || 0} · 🟢 ${c.minor || 0}（退出码 ${r.status}：2=critical/1=major/0=clean）\n所有片段已打码；明文请到对应位置核对。\n`
  return text(head + '\n' + JSON.stringify({ scope: data.scope, counts: c, findings: data.findings || [] }, null, 2))
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
