#!/bin/sh
# 跨宿主 hook 启动器：hook 进程常拿不到交互 shell 的 PATH（Devin 云端 node 不在系统 PATH，直接 `node` 会 exit 127），
# 这里自己定位 node；找不到 node 或脚本就静默放行（exit 0），护栏只做提醒 / 拦截，绝不因环境缺失打断会话。
host=""
if [ "$1" = "--host" ]; then host=$2; shift 2; fi
# Devin 会按 Claude 兼容同时读取 hooks/hooks.json；Devin 下只认根目录 hooks.json，避免同一护栏跑两遍
if [ "$host" = "claude" ] && [ -n "${DEVIN_PLUGIN_ROOT:-}" ]; then cat >/dev/null 2>&1; exit 0; fi
if [ "$host" = "antigravity" ] && [ -n "${DEVIN_PLUGIN_ROOT:-}" ]; then cat >/dev/null 2>&1; exit 0; fi
export AGENT_HOOK_HOST="$host"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 0
target="$script_dir/$1"
[ -f "$target" ] || exit 0

find_node() {
  if command -v node >/dev/null 2>&1; then command -v node; return 0; fi
  for c in "${NVM_BIN:+$NVM_BIN/node}" "$HOME/.volta/bin/node" /usr/local/bin/node /opt/homebrew/bin/node /usr/bin/node /usr/bin/nodejs; do
    [ -n "$c" ] && [ -x "$c" ] && { echo "$c"; return 0; }
  done
  for c in $(ls -d "$HOME"/.nvm/versions/node/*/bin/node /opt/hostedtoolcache/node/*/*/bin/node 2>/dev/null | sort -r); do
    [ -x "$c" ] && { echo "$c"; return 0; }
  done
  return 1
}

node_bin=$(find_node) || exit 0
project_dir="${DEVIN_PROJECT_DIR:-${CLAUDE_PROJECT_DIR:-}}"
[ -n "$project_dir" ] && [ -d "$project_dir" ] && cd "$project_dir"
exec "$node_bin" "$target"
