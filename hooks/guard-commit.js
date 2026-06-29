#!/usr/bin/env node
'use strict'
// privacy-guard 提交门（PreToolUse: Bash）。检测到 git commit 时，对**暂存内容**跑 scan.py：
//   退出码 2=critical → 阻断提交（exit 2 + 打码报告）；1=major → 警告不阻断；0/异常 → 放行。
// 复用现成 Python 引擎；python 缺失则优雅降级（不阻断正常提交，仅提示一次）。
const { spawnSync } = require('child_process')
const path = require('path')

let raw = ''
process.stdin.setEncoding('utf8')
process.stdin.on('data', function (c) { raw += c })
process.stdin.on('end', function () {
  let input
  try { input = JSON.parse(raw || '{}') } catch (e) { process.exit(0) }
  const cmd = String((input.tool_input || {}).command || '')
  // 只在 git commit 时动；用户显式 --no-verify 绕过则尊重其意图、放行
  if (!/\bgit\s+commit\b/.test(cmd)) process.exit(0)
  if (/--no-verify\b/.test(cmd)) process.exit(0)

  const cwd = input.cwd || process.cwd()
  const py = findPython()
  if (!py) {
    console.error('[privacy-guard] 提交门跳过：未找到可用的 python（扫描引擎依赖它）。装好 python 即自动生效。')
    process.exit(0)
  }
  const scan = path.join(__dirname, '..', 'skills', 'privacy-guard', 'scripts', 'scan.py')
  const r = spawnSync(py, [scan, '--mode', 'staged', '--path', cwd, '--format', 'md'], { encoding: 'utf8' })
  if (r.error || typeof r.status !== 'number') process.exit(0) // 引擎跑不起来不阻断

  if (r.status === 2) {
    console.error('[privacy-guard] ⛔ 暂存区检测到致命敏感数据(critical)，已拦下本次提交：\n')
    console.error((r.stdout || '').trim())
    console.error('\n请移除 / 脱敏后重新提交。确属误报时可 `git commit --no-verify` 跳过（自负其责）并补白名单。')
    process.exit(2)
  }
  if (r.status === 1) {
    console.error('[privacy-guard] ⚠ 暂存区有疑似敏感数据(major)，未拦截，请核实：\n')
    console.error((r.stdout || '').trim())
  }
  process.exit(0)
})

// 逐个候选验证「能真正跑 Python」——绕开 Windows 的 Microsoft Store python 假桩
function findPython () {
  for (const c of ['python3', 'python', 'py']) {
    const t = spawnSync(c, ['-c', 'import sys'], { stdio: 'ignore' })
    if (t.status === 0) return c
  }
  return null
}
