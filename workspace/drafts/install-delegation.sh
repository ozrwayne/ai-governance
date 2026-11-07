#!/bin/bash
# Human-run upgrade only. Existing register and original law texts remain intact.
set -euo pipefail
if [ "$(/usr/bin/id -u)" != 0 ] || [ -z "${SUDO_USER:-}" ] || [ "$SUDO_USER" = root ]; then
  echo 'Run in your own terminal: sudo -k /bin/bash ~/RW/governance/drafts/install-delegation.sh' >&2
  exit 1
fi
if [ ! -t 0 ]; then
  echo 'Interactive confirmation requires your terminal.' >&2
  exit 1
fi
U="$SUDO_USER"
UID_NUMBER="$(/usr/bin/id -u "$U")"
H="$(/usr/bin/python3 -I -c 'import pwd,sys; print(pwd.getpwnam(sys.argv[1]).pw_dir)' "$U")"
D="$H/RW/governance/drafts"
BASE=/Library/Governance
REG="$BASE/tools/register.py"
GATE="$BASE/gate"
SERVICE=local.governance.authorization
PLIST="/Library/LaunchDaemons/$SERVICE.plist"
PY=(/usr/bin/python3 -I)

# Verify prerequisites before changing any installed file.
for f in "$D/tools/register.py" "$D/gate/gate.py" "$D/gate/omp-gate.ts" "$D/gate/authorization.py" "$D/gate/executor.py" "$D/G-agent-config-delegation.md" "$D/S-agent-procedure-amendment/asmade.md" "$D/S-agent-procedure-amendment/statement.md" "$D/S-agent-procedure-amendment/汇编预览.md" "$H/.local/bin/omp"; do
  [ -f "$f" ] || { echo "Missing prerequisite: $f" >&2; exit 1; }
done
"${PY[@]}" "$REG" verify
/usr/sbin/visudo -c
printf '%s\n' '将安装受保护的授权服务、omp 副本、闸门与登记脚本，并提交代理动作程序法修正案。' \
  '不会覆盖宪法、原法或旧汇编，不会放宽私密范围。' \
  "本人确认账户：$U (uid $UID_NUMBER)。服务只接受该账户经 sudo 确认的任务授权。" \
  '安装期间暂停代理动作；任何失败都保留停止状态。系统口令只在 sudo 中输入。'
printf '输入「确认安装」继续：'
IFS= read -r ANSWER
[ "$ANSWER" = '确认安装' ] || { echo 'Cancelled; nothing installed.'; exit 1; }

# Use the installed stop mechanism before replacing its implementation.
sudo -u "$U" "${PY[@]}" "$GATE/gate.py" stop-request '安装委托授权与修法支持'

# Save the previous implementation once per installation, outside the legal register.
STAMP="$(/bin/date '+%Y%m%d-%H%M%S')"
BACKUP="$BASE/backups/delegation-$STAMP"
/usr/bin/install -d -o root -g wheel -m 700 "$BACKUP"
for f in "$REG" "$GATE/gate.py" "$GATE/omp-gate.ts" "$GATE/authorization.py" "$GATE/executor.py" "$GATE/authorization-config.json" "$PLIST"; do
  if [ -f "$f" ]; then /bin/cp -p "$f" "$BACKUP/$(/usr/bin/basename "$f")"; fi
done
/usr/bin/install -d -o root -g wheel -m 755 "$BASE/tools" "$GATE" "$BASE/bin" "$BASE/run"
/usr/bin/install -d -o root -g wheel -m 700 "$BASE/authorization"
/usr/bin/install -o root -g wheel -m 755 "$D/tools/register.py" "$REG"
/usr/bin/install -o root -g wheel -m 755 "$D/gate/gate.py" "$GATE/gate.py"
/usr/bin/install -o root -g wheel -m 755 "$D/gate/authorization.py" "$GATE/authorization.py"
/usr/bin/install -o root -g wheel -m 755 "$D/gate/executor.py" "$GATE/executor.py"
/usr/bin/install -o root -g wheel -m 644 "$D/gate/omp-gate.ts" "$GATE/omp-gate.ts"
/usr/bin/install -o root -g wheel -m 755 "$H/.local/bin/omp" "$BASE/bin/omp"

"${PY[@]}" - "$GATE/authorization-config.json" "$UID_NUMBER" "$U" <<'PY'
import json, os, sys
path, uid, user = sys.argv[1:]
data = {'omp': '/Library/Governance/bin/omp', 'sovereign_uid': int(uid), 'sovereign_user': user}
with open(path, 'w', encoding='utf-8') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
    f.write('\n')
os.chown(path, 0, 0)
os.chmod(path, 0o644)
PY

# Preserve append-only historical logs, but read user-owned sources without root.
# Old read-state is deliberately not imported as proof that an agent read a law.
"${PY[@]}" - "$GATE/gate.py" "$BASE/authorization" "$U" <<'PY'
import importlib.util, os, pathlib, pwd, subprocess, sys
gate_file, auth_root, user = sys.argv[1:]
spec = importlib.util.spec_from_file_location('installed_gate', gate_file)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
config, _ = gate.load_config(gate.load_index())
device, old = gate.current_device(config or {})
if device != 'mac-mini' or old is None:
    raise SystemExit('Installer configuration is for mac-mini only.')
root = pathlib.Path(auth_root) / 'runtime' / device
root.mkdir(parents=True, exist_ok=True, mode=0o700)
for folder in (root, root / 'read-state', root / 'snapshots'):
    folder.mkdir(exist_ok=True, mode=0o700)
    if folder.is_symlink() or folder.stat().st_uid != 0 or folder.stat().st_mode & 0o022:
        raise SystemExit('Unprotected runtime directory: ' + str(folder))
sources = {'records': 'records.jsonl', 'stop_requests': 'stop-requests.jsonl', 'stop_clears': 'stop-clears.jsonl'}
reader = 'import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); f=os.fdopen(fd,"rb"); import shutil; shutil.copyfileobj(f,sys.stdout.buffer)'
for key, name in sources.items():
    destination = root / name
    if destination.exists():
        if destination.is_symlink() or destination.stat().st_uid != 0:
            raise SystemExit('Unsafe existing runtime file: ' + str(destination))
        continue
    source = old[key]
    # The root-owned old clear file is publicly readable; no privileged read needed.
    with open(destination, 'xb') as target:
        os.chmod(destination, 0o600)
        result = subprocess.run(['/usr/bin/sudo', '-u', user, '/usr/bin/python3', '-I', '-c', reader, source], stdout=target)
    if result.returncode:
        destination.unlink()
        raise SystemExit('Could not migrate ' + key + '; stopped without removing source.')
print('Protected runtime:', root)
PY

# Registering the amendment displays the exact source, statement and compiled law.
# On rerun, skip only if v2 equals the approved preview, never by title alone.
"${PY[@]}" - "$BASE/register" "$D/S-agent-procedure-amendment/汇编预览.md" <<'PY'
import pathlib, sys
root, preview = map(pathlib.Path, sys.argv[1:])
v2 = root / 'S2026-002/v2.md'
if v2.exists():
    expected = preview.read_text(encoding='utf-8').replace('# 代理动作程序法（修正后汇编预览，未登记）', '# 代理动作程序法', 1)
    if v2.read_text(encoding='utf-8') != expected:
        raise SystemExit('Existing v2 differs from approved preview; stopped. Do not overwrite it.')
PY
if [ ! -f "$BASE/register/S2026-002/v2.md" ]; then
  "${PY[@]}" "$REG" amend --target S2026-002 --expected-version 1 \
    --title 代理动作程序法修正案 \
    --asmade "$D/S-agent-procedure-amendment/asmade.md" \
    --statement "$D/S-agent-procedure-amendment/statement.md"
fi
"${PY[@]}" "$REG" verify

# This one configuration publication moves privileged writes out of user directories.
# Routine task authorizations never create gazette entries.
CONFIG_CURRENT="$("${PY[@]}" - "$GATE/gate.py" "$D/G-agent-config-delegation.md" <<'PY'
import importlib.util, pathlib, sys
spec = importlib.util.spec_from_file_location('installed_gate', sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
index = gate.load_index()
_, current_id = gate.load_config(index)
entry = next(e for e in index if e['id'] == current_id)
current = pathlib.Path(gate.REGISTER, entry['latest']).read_bytes()
print('yes' if current == pathlib.Path(sys.argv[2]).read_bytes() else 'no')
PY
)"
if [ "$CONFIG_CURRENT" != yes ]; then
  "${PY[@]}" "$REG" add --kind G --title 代理动作配置 --asmade "$D/G-agent-config-delegation.md"
fi
"${PY[@]}" "$REG" verify

"${PY[@]}" - "$PLIST" "$SERVICE" <<'PY'
import os, plistlib, sys
path, label = sys.argv[1:]
data = {'Label': label, 'ProgramArguments': ['/usr/bin/python3', '-I', '/Library/Governance/gate/authorization.py', 'serve'], 'RunAtLoad': True, 'KeepAlive': True, 'UserName': 'root', 'WorkingDirectory': '/Library/Governance', 'Umask': 63, 'StandardOutPath': '/Library/Governance/authorization/service.stdout.log', 'StandardErrorPath': '/Library/Governance/authorization/service.stderr.log'}
with open(path, 'wb') as f:
    plistlib.dump(data, f)
os.chown(path, 0, 0)
os.chmod(path, 0o644)
PY
/usr/bin/plutil -lint "$PLIST"
if /bin/launchctl print "system/$SERVICE" >/dev/null 2>&1; then
  /bin/launchctl bootout "system/$SERVICE"
fi
/bin/launchctl bootstrap system "$PLIST"
/bin/launchctl print "system/$SERVICE"

printf '%s\n' '修正登记与服务安装已完成。确认后恢复代理动作；已撤销授权不会恢复。'
printf '输入「确认恢复」熄灭停止标志：'
IFS= read -r ANSWER
if [ "$ANSWER" = '确认恢复' ]; then
  "${PY[@]}" "$GATE/gate.py" stop-clear
else
  echo '停止标志保留；未恢复代理动作。'
fi
sudo -u "$U" "${PY[@]}" "$GATE/gate.py" status
printf '旧程序备份：%s\n' "$BACKUP"
echo '请关闭旧代理会话并重新打开。委托任务使用 authorization.py grant，不以普通 headless 启动冒充授权。'
