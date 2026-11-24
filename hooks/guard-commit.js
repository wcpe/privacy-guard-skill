#!/usr/bin/env node
'use strict'
// privacy-guard 提交门（PreToolUse: Claude 的 Bash / Devin 的 exec）。检测到 git commit 时，对**暂存内容**跑 scan.py：
//   退出码 2=critical → 阻断提交（exit 2 + stdout decision:block + 打码报告）；1=major → 警告不阻断；0/异常 → 放行。
// 复用现成 Python 引擎；python 缺失则优雅降级（不阻断正常提交，仅提示）。
const { spawnSync } = require('child_process')
const path = require('path')
const { findPython } = require('./find-python.cjs')

let raw = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', function (c) { raw += c })
process.stdin.on('end', function () {
  let input
  try { input = JSON.parse(raw || '{}') || {} } catch (e) { process.exit(0) }
  const ti = input.tool_input || {}
  const cmd = String(ti.command || '')
  // 只在 git commit 时动；用户显式 --no-verify 绕过则尊重其意图、放行
  if (!/\bgit\s+(?:-C\s+\S+\s+)?commit\b/.test(cmd)) process.exit(0)
  if (/--no-verify\b/.test(cmd)) process.exit(0)

  // 提交实际发生的仓库：Devin exec 的 workdir、命令开头的 `cd <dir> &&`、`git -C <dir>`，否则为事件 cwd / hook cwd
  const unquote = function (s) { return s.replace(/^["']|["']$/g, '') }
  let cwd = String(ti.workdir || input.cwd || process.cwd())
  const cd = cmd.match(/^\s*cd\s+("[^"]+"|'[^']+'|[^\s;&|]+)\s*&&/)
  if (cd) cwd = path.resolve(cwd, unquote(cd[1]))
  const gc = cmd.match(/\bgit\s+-C\s+("[^"]+"|'[^']+'|\S+)\s+commit\b/)
  if (gc) cwd = path.resolve(cwd, unquote(gc[1]))

  const py = findPython()
  if (!py) {
    console.error('[privacy-guard] 提交门跳过：未找到可用的 python（扫描引擎依赖它）。装好 python 即自动生效。')
    process.exit(0)
  }
  const scan = path.join(__dirname, '..', 'skills', 'privacy-guard', 'scripts', 'scan.py')
  const r = spawnSync(py, [scan, '--mode', 'staged', '--path', cwd, '--format', 'md'], { encoding: 'utf8' })
  if (r.error || typeof r.status !== 'number') process.exit(0) // 引擎跑不起来不阻断

  const report = (r.stdout || '').trim()
  if (r.status === 2) {
    const reason = '[privacy-guard] ⛔ 暂存区检测到致命敏感数据(critical)，已拦下本次提交：\n\n' + report +
      '\n\n请移除 / 脱敏后重新提交。确属误报时可 `git commit --no-verify` 跳过（自负其责）并补白名单。'
    process.stdout.write(JSON.stringify({ decision: 'block', reason: reason }) + '\n')
    console.error(reason)
    process.exit(2)
  }
  if (r.status === 1) {
    console.error('[privacy-guard] ⚠ 暂存区有疑似敏感数据(major)，未拦截，请核实：\n\n' + report)
  }
  process.exit(0)
})
