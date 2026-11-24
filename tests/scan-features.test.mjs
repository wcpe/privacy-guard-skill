import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, rmSync, mkdirSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN = path.join(repoRoot, 'skills', 'privacy-guard', 'scripts', 'scan.py');
// 拼接出的假凭证，避免测试源码本身被扫描器命中
const AWS = 'AKIA' + 'Q3EXAMPLE7ZK4NB2';
const GLPAT = 'glp' + 'at-' + 'Zx8Kq2Lm9Np4Rs7Tv1Wy';
const NPM = 'npm' + '_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';

function repo(files) {
  const dir = mkdtempSync(path.join(tmpdir(), 'pg-scan-'));
  const git = (...a) => execFileSync('git', a, { cwd: dir, stdio: 'ignore' });
  git('init', '-q'); git('config', 'user.email', 't@t'); git('config', 'user.name', 't');
  for (const [f, c] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    writeFileSync(path.join(dir, f), c);
  }
  return { dir, git };
}
const scan = (dir, ...a) => spawnSync('python3', [SCAN, '--path', dir, ...a], { encoding: 'utf8' });
const json = (dir, ...a) => { const r = scan(dir, '--format', 'json', ...a); return { r, d: JSON.parse(r.stdout) }; };

test('新增凭证规则命中且打码', () => {
  const { dir } = repo({ 'a.txt': `gl = ${GLPAT}\nnpm = ${NPM}\n` });
  try {
    const { r, d } = json(dir, '--mode', 'worktree');
    assert.equal(r.status, 2);
    assert.deepEqual(d.findings.map((f) => f.rule).sort(), ['gitlab-token', 'npm-token']);
    assert.ok(!r.stdout.includes(GLPAT) && !r.stdout.includes(NPM), '不能落明文');
    assert.ok(d.findings.every((f) => /^[0-9a-f]{16}$/.test(f.fingerprint)));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('行内豁免、配置 allow / ignore_paths / severity 生效且计入豁免数', () => {
  const { dir } = repo({
    'a.txt': `k1 = ${AWS} # privacy-guard:allow aws-access-key-id\nk2 = ${AWS} # privacy-guard:allow email\n`,
    'fixtures/b.txt': `k = ${AWS}\n`,
    'c.txt': 'ip = 10.1.2.3\n',
    '.privacy-guard.json': JSON.stringify({
      ignore_paths: ['fixtures/**'],
      severity: { 'private-ipv4': 'off' },
    }),
  });
  try {
    const { d } = json(dir, '--mode', 'worktree');
    assert.deepEqual(d.findings.map((f) => `${f.path}:${f.line}`), ['a.txt:2'], '只豁免指定规则');
    assert.equal(d.suppressed.inline, 1);
    assert.equal(d.suppressed.config, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// 给 15 位数字补 Luhn 校验位，运行时拼出能过 Luhn 的卡号样例
const luhn = (body) => {
  let sum = 0;
  [...body].reverse().forEach((c, i) => { let d = +c; if (i % 2 === 0) { d *= 2; if (d > 9) d -= 9; } sum += d; });
  return body + ((10 - (sum % 10)) % 10);
};
const CARD = luhn('622202100112345');

test('十六进制校验和里的数字串、包名里的 .internal 段不误报；真卡号与内网主机名照报', () => {
  const host = 'build01' + '.corp';
  const { dir } = repo({
    'Cargo.lock': `checksum = "93${'ab'}${CARD}f8b2ff13f34540b44e946ef35111825727b38d33286ef9861"\n`,
    'Layout.kt': 'package top.wcpe.allincore.layout.engine.internal.taffy\n' +
      'import top.wcpe.allincore.layout.engine.internal.taffy.Node\n' +
      'val n = top.wcpe.allincore.layout.engine.internal.taffy.Node()\n',
    'real.txt': `card = ${CARD}\nhost = ${host}\ntel = 1${'3812345678'}ext.12\n`,
  });
  try {
    const { d } = json(dir, '--mode', 'worktree');
    assert.deepEqual(d.findings.map((f) => `${f.path}:${f.rule}`).sort(), ['real.txt:bank-card', 'real.txt:cn-mobile', 'real.txt:internal-hostname']);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('已豁免项在报告里逐条列出规则、位置与理由', () => {
  const { dir } = repo({
    'a.txt': `k = ${AWS}\n`,
    '.privacy-guard.json': JSON.stringify({ allow: [{ rule: 'aws-access-key-id', path: 'a.txt', reason: '文档示例' }] }),
  });
  try {
    const { r, d } = json(dir, '--mode', 'worktree');
    assert.equal(r.status, 0);
    assert.deepEqual(d.suppressed_items.map((f) => [f.kind, f.rule, f.path, f.line]), [['config', 'aws-access-key-id', 'a.txt', 1]]);
    assert.match(d.suppressed_items[0].reason, /文档示例/);
    const md = scan(dir, '--mode', 'worktree', '--format', 'md').stdout;
    assert.match(md, /## 已豁免/);
    assert.match(md, /文档示例/);
    assert.ok(!md.includes(AWS) && !r.stdout.includes(AWS), '豁免明细也不能落明文');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('fail_on 取值非法是配置错误（退出码 3）', () => {
  const { dir } = repo({ '.privacy-guard.json': JSON.stringify({ fail_on: 'high' }) });
  try {
    assert.equal(scan(dir, '--mode', 'worktree').status, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('allow 缺 reason 是配置错误（退出码 3）', () => {
  const { dir } = repo({ '.privacy-guard.json': JSON.stringify({ allow: [{ rule: 'email' }] }) });
  try {
    const r = scan(dir, '--mode', 'worktree');
    assert.equal(r.status, 3);
    assert.match(r.stderr, /reason/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('基线：写入后只报新增，基线文件不含明文', () => {
  const { dir } = repo({
    'old.txt': `k = ${AWS}\n`,
    '.privacy-guard.json': JSON.stringify({ baseline: '.privacy-guard-baseline.json' }),
  });
  try {
    assert.equal(scan(dir, '--mode', 'worktree', '--write-baseline', path.join(dir, '.privacy-guard-baseline.json')).status, 0);
    const base = readFileSync(path.join(dir, '.privacy-guard-baseline.json'), 'utf8');
    assert.ok(!base.includes(AWS));
    assert.ok(JSON.parse(base).findings.every((x) => !('match' in x)), '基线不存片段');
    const clean = json(dir, '--mode', 'worktree');
    assert.equal(clean.r.status, 0);
    assert.equal(clean.d.suppressed.baseline, 1);
    writeFileSync(path.join(dir, 'new.txt'), `t = ${GLPAT}\n`);
    const again = json(dir, '--mode', 'worktree');
    assert.deepEqual(again.d.findings.map((f) => f.path), ['new.txt']);
    assert.equal(json(dir, '--mode', 'worktree', '--no-baseline').d.findings.length, 2);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('--since 只扫区间新增并带提交；无效 ref 退出码 3', () => {
  const { dir, git } = repo({ 'old.txt': `k = ${AWS}\n` });
  try {
    git('add', '.'); git('commit', '-qm', 'old'); git('tag', 'v1');
    writeFileSync(path.join(dir, 'new.txt'), `t = ${GLPAT}\n`);
    writeFileSync(path.join(dir, '.env'), 'X=1\n');
    git('add', '.'); git('commit', '-qm', 'feat: new');
    const { r, d } = json(dir, '--since', 'v1');
    assert.equal(r.status, 2);
    assert.deepEqual(d.findings.map((f) => f.rule).sort(), ['dotenv-file', 'gitlab-token']);
    assert.ok(d.findings.every((f) => /^[0-9a-f]{7,}$/.test(f.commit)), '只带提交号，不带可能含敏感信息的提交标题');
    assert.equal(scan(dir, '--since', 'no-such-ref').status, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('区间扫描覆盖二进制 / 空的敏感文件、中文路径与合并提交里新写入的内容', () => {
  const { dir, git } = repo({ 'a.txt': 'base\n' });
  try {
    git('add', '.'); git('commit', '-qm', 'base'); git('tag', 'v1');
    writeFileSync(path.join(dir, 'cert.p12'), Buffer.from([0, 1, 2, 0, 255]));
    writeFileSync(path.join(dir, '.env'), '');
    mkdirSync(path.join(dir, '配置'));
    writeFileSync(path.join(dir, '配置', '说明.txt'), `k = ${GLPAT}\n`);
    git('add', '.'); git('commit', '-qm', 'add');
    git('checkout', '-qb', 'side'); writeFileSync(path.join(dir, 'a.txt'), 'side\n'); git('commit', '-qam', 'side');
    git('checkout', '-q', '-'); writeFileSync(path.join(dir, 'a.txt'), 'main\n'); git('commit', '-qam', 'main');
    spawnSync('git', ['merge', '-q', 'side'], { cwd: dir });
    writeFileSync(path.join(dir, 'a.txt'), `resolved ${NPM}\n`);
    git('add', 'a.txt'); git('commit', '-qm', 'merge');
    assert.equal(execFileSync('git', ['rev-list', '--parents', '-n1', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim().split(' ').length, 3, '确实生成了合并提交');
    const { d } = json(dir, '--since', 'v1');
    const got = d.findings.map((f) => `${f.rule}@${f.path}`).sort();
    assert.ok(got.includes('pkcs12-file@cert.p12') || got.some((g) => g.endsWith('@cert.p12')), got.join());
    assert.ok(got.some((g) => g.endsWith('@.env')), got.join());
    assert.ok(got.includes('gitlab-token@配置/说明.txt'), got.join());
    assert.ok(got.includes('npm-token@a.txt'), got.join());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('功能分支同步目标分支时，目标分支既有内容不算新增；含空格路径可按精确路径豁免', () => {
  const { dir, git } = repo({ 'a.txt': 'base\n' });
  try {
    git('add', '.'); git('commit', '-qm', 'base'); git('branch', 'main0');
    git('checkout', '-qb', 'feature'); git('checkout', '-q', 'main0');
    writeFileSync(path.join(dir, 'old.txt'), `k = ${GLPAT}\n`);
    writeFileSync(path.join(dir, '.env'), 'X=1\n');
    git('add', '.'); git('commit', '-qm', 'main side');
    git('checkout', '-q', 'feature');
    mkdirSync(path.join(dir, '我的 目录'));
    writeFileSync(path.join(dir, '我的 目录', 'x.txt'), `k = ${NPM}\n`);
    writeFileSync(path.join(dir, '.privacy-guard.json'), JSON.stringify({ allow: [{ path: '我的 目录/x.txt', reason: '测试夹具' }] }));
    git('add', '.'); git('commit', '-qm', 'feat');
    git('merge', '-q', '--no-edit', 'main0');
    assert.equal(execFileSync('git', ['rev-list', '--parents', '-n1', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim().split(' ').length, 3);
    const { r, d } = json(dir, '--since', 'main0');
    assert.deepEqual(d.findings, [], JSON.stringify(d.findings));
    assert.equal(r.status, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('--fail-on 门槛与 SARIF 输出', () => {
  const { dir } = repo({ 'a.txt': 'host = db.corp\n' });
  try {
    assert.equal(scan(dir, '--mode', 'worktree', '--format', 'md').status, 1);
    assert.equal(scan(dir, '--mode', 'worktree', '--format', 'md', '--fail-on', 'critical').status, 0);
    const r = scan(dir, '--mode', 'worktree', '--format', 'sarif', '--fail-on', 'never');
    assert.equal(r.status, 0);
    const s = JSON.parse(r.stdout);
    assert.equal(s.version, '2.1.0');
    const res = s.runs[0].results[0];
    assert.equal(res.ruleId, 'internal-hostname');
    assert.equal(res.level, 'warning');
    assert.equal(res.locations[0].physicalLocation.region.startLine, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('install_hook.py：装进 core.hooksPath，已有他人钩子时不覆盖', () => {
  const { dir, git } = repo({ 'a.txt': `k = ${AWS}\n` });
  try {
    git('config', 'core.hooksPath', '.husky');
    mkdirSync(path.join(dir, '.husky'));
    writeFileSync(path.join(dir, '.husky', 'pre-commit'), '#!/bin/sh\necho other\n');
    const r = spawnSync('python3', [path.join(repoRoot, 'skills', 'privacy-guard', 'scripts', 'install_hook.py'), '--path', dir], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(existsSync(path.join(dir, '.husky', 'pre-commit.privacy-guard')));
    assert.ok(existsSync(path.join(dir, '.husky', 'privacy_scan.py')));
    assert.match(readFileSync(path.join(dir, '.husky', 'pre-commit'), 'utf8'), /echo other/);
    git('config', '--unset', 'core.hooksPath');
    spawnSync('python3', [path.join(repoRoot, 'skills', 'privacy-guard', 'scripts', 'install_hook.py'), '--path', dir]);
    git('add', 'a.txt');
    const c = spawnSync('git', ['commit', '-qm', 'x'], { cwd: dir, encoding: 'utf8' });
    assert.notEqual(c.status, 0, '装好的钩子要拦下 critical 提交');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('仓库自扫在自身 .privacy-guard.json 下干净', () => {
  assert.equal(scan(repoRoot, '--mode', 'worktree', '--format', 'md').status, 0);
});
