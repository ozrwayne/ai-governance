#!/bin/bash
# Run as the human user after install-delegation.sh; sudo asks for the user's password.
set -euo pipefail
if [ "$(/usr/bin/id -u)" = 0 ]; then
  echo 'Run this script without sudo; the grant command will ask for your password.' >&2
  exit 1
fi
AUTH=/Library/Governance/gate/authorization.py
[ -f "$AUTH" ] || { echo 'Install the delegated authorization implementation first.' >&2; exit 1; }
SCOPE="$(/usr/bin/mktemp -t governance-skill-scope)"
trap '/bin/rm -f "$SCOPE"' EXIT
PROMPT='我知道推文流水线该重建，方案都写好了，可一直拖着没动手，不知道卡在哪。帮我解决。'
/usr/bin/python3 -I - "$SCOPE" "$PROMPT" "$HOME/RW" <<'PY'
import json, sys, time
path, prompt, root = sys.argv[1:]
scope = {
    'original_command': prompt,
    'goal': '测试代理能否自动选择并读取适用技能，给出执行阻滞诊断；不修改资料、不运行外部命令、不发布内容。',
    'expires_at': time.time() + 900,
    'actions': ['internal', 'delegate'],
    'paths': [root],
    'commands': [],
    'operations': [],
    'irreversible_writes': False,
}
with open(path, 'w', encoding='utf-8') as f:
    json.dump(scope, f, ensure_ascii=False, indent=2)
    f.write('\n')
PY
sudo -k /usr/bin/python3 -I "$AUTH" grant --scope "$SCOPE" --prompt "$PROMPT" --cwd "$HOME/RW"
