import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (...p) => JSON.parse(readFileSync(path.join(repoRoot, ...p), 'utf8'));
// 拼接出的假密钥，避免测试源码本身被扫描器命中
const FAKE_KEY = 'AKIA' + 'Q3EXAMPLE7ZK4NB2';

function stagedRepo(content) {
  const dir = mkdtempSync(path.join(tmpdir(), 'pg-hook-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  git('init', '-q');
  writeFileSync(path.join(dir, 'config.txt'), content);
  git('add', 'config.txt');
  return dir;
}

function runHook(input, { host = 'devin', env = {} } = {}) {
  return spawnSync('sh', [path.join(repoRoot, 'hooks', 'run-hook.sh'), '--host', host, 'guard-commit.js'], {
    cwd: tmpdir(), input: JSON.stringify(input), encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
  });
}

test('三份清单版本一致，Devin 清单内联 MCP、根 hooks.json 匹配 exec 并按 DEVIN_PLUGIN_ROOT 定位', () => {
  const devin = readJson('.devin-plugin', 'plugin.json');
  assert.equal(devin.version, readJson('.claude-plugin', 'plugin.json').version);
  assert.equal(devin.version, readJson('.codex-plugin', 'plugin.json').version);
  assert.match(readFileSync(path.join(repoRoot, 'mcp', 'privacy-mcp.mjs'), 'utf8'), new RegExp(`version: '${devin.version}'`));
  assert.deepEqual(devin.mcpServers['privacy-guard'].args, ['mcp/privacy-mcp.mjs']);
  const hooks = readJson('hooks.json');
  assert.equal(hooks.PreToolUse[0].matcher, '^exec$');
  assert.match(hooks.PreToolUse[0].hooks[0].command, /DEVIN_PLUGIN_ROOT.*--host devin/);
  assert.match(readJson('hooks', 'hooks.json').hooks.PreToolUse[0].hooks[0].command, /--host claude/);
});

test('Devin exec 的 workdir 指向含 critical 暂存内容的仓库时阻断并输出 decision:block', () => {
  const dir = stagedRepo(`aws_access_key_id = ${FAKE_KEY}\n`);
  try {
    const r = runHook({ tool_name: 'exec', tool_input: { command: 'git commit -m "feat: x"', workdir: dir } });
    assert.equal(r.status, 2, r.stderr);
    assert.equal(JSON.parse(r.stdout).decision, 'block');
    assert.doesNotMatch(r.stdout, new RegExp(FAKE_KEY), '报告必须打码');
    const cd = runHook({ tool_name: 'exec', tool_input: { command: `cd "${dir}" && git commit -m "feat: x"` } });
    assert.equal(cd.status, 2, '命令开头 cd 进仓库也要生效');
    const bypass = runHook({ tool_name: 'exec', tool_input: { command: 'git commit --no-verify -m x', workdir: dir } });
    assert.equal(bypass.status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('干净暂存放行；Devin 下 Claude 配置被跳过、纯 Claude 环境仍拦截', () => {
  const clean = stagedRepo('hello\n');
  const dirty = stagedRepo(`aws_access_key_id = ${FAKE_KEY}\n`);
  try {
    assert.equal(runHook({ tool_name: 'exec', tool_input: { command: 'git commit -m x', workdir: clean } }).status, 0);
    const input = { tool_name: 'Bash', cwd: dirty, tool_input: { command: 'git commit -m x' } };
    assert.equal(runHook(input, { host: 'claude', env: { DEVIN_PLUGIN_ROOT: repoRoot } }).status, 0);
    assert.equal(runHook(input, { host: 'claude', env: { CLAUDE_PLUGIN_ROOT: repoRoot } }).status, 2);
  } finally {
    rmSync(clean, { recursive: true, force: true });
    rmSync(dirty, { recursive: true, force: true });
  }
});

test('MCP 在插件目录启动且未传 path 时提示传 path，而不是误扫插件自身', () => {
  const req = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'privacy_scan', arguments: {} } },
  ].map((m) => JSON.stringify(m)).join('\n') + '\n';
  const env = { PATH: process.env.PATH, HOME: process.env.HOME };
  const r = spawnSync('node', ['mcp/privacy-mcp.mjs'], { cwd: repoRoot, input: req, encoding: 'utf8', env });
  const res = r.stdout.trim().split('\n').map((l) => JSON.parse(l)).find((m) => m.id === 2).result;
  assert.equal(res.isError, true);
  assert.match(res.content[0].text, /path/);
});

test('git -C 带引号的含空格路径、&& 串联多个仓库提交时，逐个扫描并拦截任一 critical', () => {
  const clean = stagedRepo('hello\n');
  const spaced = mkdtempSync(path.join(tmpdir(), 'pg hook '));
  execFileSync('git', ['init', '-q'], { cwd: spaced, stdio: 'ignore' });
  writeFileSync(path.join(spaced, 'config.txt'), `aws_access_key_id = ${FAKE_KEY}\n`);
  execFileSync('git', ['add', 'config.txt'], { cwd: spaced, stdio: 'ignore' });
  try {
    const quoted = runHook({ tool_name: 'exec', tool_input: { command: `git -C "${spaced}" commit -m x` } });
    assert.equal(quoted.status, 2, '引号包住的含空格路径也要识别');
    const chained = runHook({ tool_name: 'exec', tool_input: { command: `git -C ${clean} commit -m a && git -C "${spaced}" commit -m b` } });
    assert.equal(chained.status, 2, '第二个仓库的 critical 也要拦');
    assert.doesNotMatch(chained.stdout, new RegExp(FAKE_KEY));
  } finally {
    rmSync(clean, { recursive: true, force: true });
    rmSync(spaced, { recursive: true, force: true });
  }
});

test('MCP 的相对 path 以宿主项目根为基准解析，而不是插件目录', () => {
  const proj = stagedRepo('hello\n');
  const req = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2024-11-05' } },
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'privacy_scan', arguments: { path: '.' } } },
  ].map((m) => JSON.stringify(m)).join('\n') + '\n';
  try {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, DEVIN_PROJECT_DIR: proj };
    const r = spawnSync('node', ['mcp/privacy-mcp.mjs'], { cwd: repoRoot, input: req, encoding: 'utf8', env });
    const res = r.stdout.trim().split('\n').map((l) => JSON.parse(l)).find((m) => m.id === 2).result;
    assert.equal(res.isError, false, res.content[0].text);
    assert.ok(res.content[0].text.includes(proj), '应扫描项目目录');
  } finally { rmSync(proj, { recursive: true, force: true }); }
});
