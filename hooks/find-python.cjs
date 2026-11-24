'use strict'
// 找一个「能真正跑 Python」的解释器：先试 PATH，再试常见绝对路径（hook / MCP 进程常拿不到交互 shell 的 PATH）。
// 逐个实际执行验证，绕开 Windows 的 Microsoft Store python 假桩。
const { spawnSync } = require('child_process')
const fs = require('fs')
const path = require('path')
const os = require('os')

function candidates () {
  const home = os.homedir()
  const list = ['python3', 'python', 'py',
    '/usr/bin/python3', '/usr/local/bin/python3', '/opt/homebrew/bin/python3',
    path.join(home, '.pyenv', 'shims', 'python3')]
  for (const base of [path.join(home, '.pyenv', 'versions'), '/opt/hostedtoolcache/Python']) {
    try {
      for (const v of fs.readdirSync(base).sort().reverse()) {
        list.push(path.join(base, v, 'bin', 'python3'), path.join(base, v, 'x64', 'bin', 'python3'))
      }
    } catch (e) {}
  }
  return list
}

function findPython () {
  for (const c of candidates()) {
    if (path.isAbsolute(c) && !fs.existsSync(c)) continue
    const t = spawnSync(c, ['-c', 'import sys'], { stdio: 'ignore' })
    if (t.status === 0) return c
  }
  return null
}

module.exports = { findPython }
