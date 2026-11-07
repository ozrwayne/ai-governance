#!/bin/bash
# Installs the gate program and registers S2026-002 with its configuration gazette.
# Run in your own terminal:  sudo /bin/bash ~/RW/governance/drafts/install.sh
# Each registration shows the exact text and waits for 「确认」 (C2026-001 D4).
set -euo pipefail

if [ "$(id -u)" != 0 ] || [ -z "${SUDO_USER:-}" ]; then
	echo "run with: sudo /bin/bash $0" >&2
	exit 1
fi
U="$SUDO_USER"
H="$(dscl . -read "/Users/$U" NFSHomeDirectory | awk '{print $2}')"
D="$H/RW/governance/drafts"
G="$H/RW/governance"
PY=(/usr/bin/python3 -I)
REG=/Library/Governance/tools/register.py
GATE=/Library/Governance/gate

echo "== 1. 登记脚本升级（索引载明适用的动作类别，S2026-001 §10）"
install -o root -g wheel -m 755 "$D/tools/register.py" "$REG"
"${PY[@]}" "$REG" verify

echo "== 2. 闸门程序"
install -d -o root -g wheel -m 755 "$GATE" /Library/Governance/stop
install -o root -g wheel -m 755 "$D/gate/gate.py" "$GATE/gate.py"
install -o root -g wheel -m 644 "$D/gate/omp-gate.ts" "$GATE/omp-gate.ts"
touch /Library/Governance/stop/clears.jsonl
chown root:wheel /Library/Governance/stop/clears.jsonl
chmod 644 /Library/Governance/stop/clears.jsonl

echo "== 3. 停止请求与记录文件：只能追加"
install -d -o "$U" -g staff -m 755 "$G/stop" "$G/state" "$G/snapshots" "$G/records/mac-mini"
for f in "$G/stop/requests.jsonl" "$G/records/mac-mini/records.jsonl"; do
	# Already append-only from an earlier run: leave it untouched.
	if [ -e "$f" ] && /bin/ls -lO "$f" | grep -q sappnd; then
		continue
	fi
	touch "$f"
	chown "$U:staff" "$f"
	chmod 644 "$f"
	chflags sappnd "$f"
done

echo "== 4. 接入 omp 与 Claude Code"
sudo -u "$U" /usr/bin/python3 -I - "$H/.omp/agent/config.yml" "$GATE/omp-gate.ts" <<'PYEOF'
import sys
path, ext = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().splitlines()
if not any(l.strip() == "- " + ext for l in lines):
    if "extensions:" in [l.strip() for l in lines]:
        at = [l.strip() for l in lines].index("extensions:")
        lines.insert(at + 1, "  - " + ext)
    else:
        lines += ["extensions:", "  - " + ext]
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
print("omp config:", path)
PYEOF
install -d -o root -g wheel -m 755 "/Library/Application Support/ClaudeCode"
cat > "/Library/Application Support/ClaudeCode/managed-settings.json" <<JSON
{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/python3 -I $GATE/gate.py claude"}]}
    ]
  }
}
JSON
chown root:wheel "/Library/Application Support/ClaudeCode/managed-settings.json"
chmod 644 "/Library/Application Support/ClaudeCode/managed-settings.json"

echo "== 5. 登记：宪法与登记法的适用动作类别、代理动作程序法、代理动作配置公报"
if grep -q '"代理动作程序法"' /Library/Governance/register/index.yaml; then
	echo "已登记，跳过（登记只能追加，重复运行不再写入）"
else
	"${PY[@]}" "$REG" meta --target C2026-001 --applies '*'
	"${PY[@]}" "$REG" meta --target S2026-001 --applies register
	"${PY[@]}" "$REG" add --kind S --title 代理动作程序法 --applies '*' \
		--asmade "$D/S-agent-procedure/asmade.md" --statement "$D/S-agent-procedure/statement.md"
	"${PY[@]}" "$REG" add --kind G --title 代理动作配置 --asmade "$D/G-agent-config.md"
fi

echo "== 6. 核验"
"${PY[@]}" "$REG" verify
ls -lO "$G/stop/requests.jsonl" "$G/records/mac-mini/records.jsonl"
sudo -u "$U" "${PY[@]}" "$GATE/gate.py" status
echo "完成。新开的 omp 与 Claude Code 会话起受闸门审查。"
