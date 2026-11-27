import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const readJson = (...p) => JSON.parse(readFileSync(path.join(repoRoot, ...p), 'utf8'));
const FAKE_KEY = 'AKIA' + 'Q3EXAMPLE7ZK4NB2';

function stagedRepo(content) {
  const dir = mkdtempSync(path.join(tmpdir(), 'pg-agy-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  git('init', '-q');
  writeFileSync(path.join(dir, 'config.txt'), content);
  git('add', 'config.txt');
  return dir;
}

function runHook(input, { host = 'antigravity', env = {} } = {}) {
  return spawnSync('sh', [path.join(repoRoot, 'hooks', 'run-hook.sh'), '--host', host, 'guard-commit.js'], {
    cwd: repoRoot,
    input: JSON.stringify(input),
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME, ...env },
  });
}

test('Antigravity 插件清单与 MCP 配置合法且版本与其余三端一致', () => {
  const agy = readJson('.antigravity-plugin', 'plugin.json');
  assert.equal(agy.$schema, 'https://antigravity.google/schemas/v1/plugin.json');
  assert.match(agy.name, /^[a-z0-9]+(-[a-z0-9]+)*$/);
  assert.equal(agy.version, readJson('.devin-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.claude-plugin', 'plugin.json').version);
  assert.equal(agy.version, readJson('.codex-plugin', 'plugin.json').version);
  assert.ok(Array.isArray(agy.suggestedPrompts) && agy.suggestedPrompts.length <= 3);

  const mcp = readJson('mcp_config.json');
  assert.deepEqual(mcp.mcpServers['privacy-guard'].args, ['${PLUGIN_ROOT}/mcp/privacy-mcp.mjs']);
});

test('Antigravity PreToolUse 提交门：命中 critical 返回 exit 0 + decision:deny 且报告打码，干净暂存返回 {}', () => {
  const dirty = stagedRepo(`aws_access_key_id = ${FAKE_KEY}\n`);
  const clean = stagedRepo('hello\n');
  try {
    const blocked = runHook({
      toolCall: { name: 'run_command', args: { CommandLine: 'git commit -m "feat: x"', Cwd: dirty } },
      workspacePaths: [dirty],
    });
    assert.equal(blocked.status, 0, 'Antigravity 阻断必须退出码 0');
    const out = JSON.parse(blocked.stdout);
    assert.equal(out.decision, 'deny');
    assert.doesNotMatch(out.reason, new RegExp(FAKE_KEY), '报告必须打码');

    const allowed = runHook({
      toolCall: { name: 'run_command', args: { CommandLine: 'git commit -m "feat: x"', Cwd: clean } },
      workspacePaths: [clean],
    });
    assert.equal(allowed.status, 0);
    assert.deepEqual(JSON.parse(allowed.stdout), {});
  } finally {
    rmSync(dirty, { recursive: true, force: true });
    rmSync(clean, { recursive: true, force: true });
  }
});
