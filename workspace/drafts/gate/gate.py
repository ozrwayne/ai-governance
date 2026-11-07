#!/usr/bin/env python3
"""Gate program designated by gazette under S2026-002 (代理动作程序法).

Every agent action passes here before it runs (§3, §4). The gate reads its
configuration from the latest registered gazette titled 代理动作配置, so the
configuration changes only through a password-confirmed registration.

  gate.py decide JSON      omp extension: prints {"decision", "reason", "prompt"}
  gate.py outcome JSON     omp extension: records successful complete law reads
  gate.py claude           Claude Code PreToolUse hook (JSON on stdin)
  gate.py stop-request SOURCE   §7: light the stop flag (any agent, any source)
  gate.py stop-clear       §7: extinguish the stop flag (sudo only)
  gate.py status           print stop flag, device and required readings
"""

import datetime
import importlib.util
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import sys

REGISTER = "/Library/Governance/register"
CONFIG_TITLE = "代理动作配置"
INTERNAL_SCHEMES = ("local://", "artifact://", "agent://", "history://", "omp://", "skill://", "out://", "mcp://", "rule://")
WEB_SCHEMES = ("http://", "https://", "ssh://")



def now():
    return datetime.datetime.now().astimezone().isoformat(timespec="microseconds")


# ---------------------------------------------------------------- register

def load_index():
    entries, current = [], None
    with open(os.path.join(REGISTER, "index.yaml"), encoding="utf-8") as f:
        for line in f:
            if line.startswith("  - id: "):
                current = {"id": json.loads(line[len("  - id: "):])}
                entries.append(current)
            elif current is not None and line.startswith("    ") and ": " in line:
                key, value = line.strip().split(": ", 1)
                current[key] = json.loads(value)
    return entries


def load_config(index):
    gazettes = [e for e in index if e.get("kind") == "G" and e.get("title") == CONFIG_TITLE]
    if not gazettes:
        return None, None
    entry = gazettes[-1]
    with open(os.path.join(REGISTER, entry["latest"]), encoding="utf-8") as f:
        text = f.read()
    block = re.search(r"```json\n(.*?)\n```", text, re.S)
    return (json.loads(block.group(1)) if block else None), entry["id"]


def current_device(config):
    names = {socket.gethostname().split(".")[0]}
    for name, spec in config.get("devices", {}).items():
        if spec.get("hostname") in names:
            return name, spec
    return None, None


def basis_label(index, entry_id, article):
    for e in index:
        if e["id"] == entry_id:
            version = e["latest"].rsplit("/v", 1)[-1].split(".")[0] if "/v" in e["latest"] else "1"
            return "%s v%s %s" % (entry_id, version, article)
    return "%s %s" % (entry_id, article)


def required_readings(index, category):
    paths = []
    for e in index:
        if e.get("kind") == "G":
            continue
        applies = e.get("applies", [])
        if "*" in applies or category in applies:
            paths.append(os.path.join(REGISTER, e["latest"]))
    return paths


# ---------------------------------------------------------------- state & records

def append_line(path, record):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def last_time(path):
    if not os.path.exists(path):
        return ""
    last = ""
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = json.loads(line).get("at", last)
    return last


def stop_lit(spec):
    requested = last_time(spec["stop_requests"])
    # Equal timestamps are ambiguous: conservatively keep the stop flag lit.
    return bool(requested) and requested >= last_time(spec["stop_clears"])


def state_path(spec, session):
    return os.path.join(spec["state"], hashlib.sha256(session.encode("utf-8")).hexdigest()[:32] + ".json")


def load_state(spec, session):
    try:
        with open(state_path(spec, session), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"read": []}


def save_state(spec, session, state):
    os.makedirs(spec["state"], exist_ok=True)
    tmp = state_path(spec, session) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)
    os.replace(tmp, state_path(spec, session))


def snapshot(spec, session, path):
    folder = os.path.join(spec["snapshots"], hashlib.sha256(session.encode("utf-8")).hexdigest()[:32])
    os.makedirs(folder, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    dest = os.path.join(folder, stamp + "-" + os.path.basename(path))
    shutil.copy2(path, dest)
    return dest


# ---------------------------------------------------------------- paths

def resolve(path, cwd):
    path = os.path.expanduser(path.strip())
    if not os.path.isabs(path):
        path = os.path.join(cwd or os.getcwd(), path)
    return os.path.realpath(path)


def strip_selector(path):
    # omp read paths may carry ":50-80", ":raw" and similar suffixes.
    candidate = path
    for _ in range(3):
        if os.path.exists(candidate) or ":" not in os.path.basename(candidate):
            return candidate
        candidate = candidate.rsplit(":", 1)[0]
    return candidate


def under(path, roots):
    path = os.path.realpath(path)
    roots = [os.path.realpath(r) for r in roots]
    return any(path == r or path.startswith(r.rstrip("/") + "/") for r in roots)


def contains(path, roots):
    # path is an ancestor of a root: a recursive scan of path reaches the root.
    path = os.path.realpath(path)
    roots = [os.path.realpath(r) for r in roots]
    return any(r == path or r.startswith(path.rstrip("/") + "/") for r in roots)


def internal_roots(spec):
    # Records of every device, stop requests, per-session state and write snapshots.
    # Exact configured paths only: a temporary test register must not become protected
    # merely because it shares a parent with a record file.
    return [os.path.dirname(spec["records"]), os.path.dirname(spec["stop_requests"]), spec["state"], spec["snapshots"]]


def write_protected(spec, path):
    if under(path, ["/Library/Governance"] + spec.get("protected", []) + internal_roots(spec)):
        return True
    parts = path.split("/")
    return ".omp" in parts or (".claude" in parts and os.path.basename(path).startswith("settings"))


# ---------------------------------------------------------------- classification

def classify_bash(command, cwd):
    # A shell is a program, not a read tool: aliases, flags, substitutions and
    # helpers cannot be safely recognized by a command-name allowlist.
    return "exec", [], False


def edit_targets(text):
    targets = re.findall(r"^\[(.+?)#[0-9A-Fa-f]{4}\]", text or "", re.M)
    for destination in re.findall(r"^MV (.+)$", text or "", re.M):
        values = shlex.split(destination)
        if len(values) != 1:
            raise ValueError("ambiguous edit move destination")
        targets.append(values[0])
    return targets


def classify(client, tool, inp, cwd):
    """Return dict(category, reads, writes, scans, summary)."""
    inp = inp or {}
    out = {"category": "exec", "reads": [], "writes": [], "scans": [], "summary": tool}

    def local_read(p):
        if p.startswith(INTERNAL_SCHEMES) or p.startswith("xd://"):
            return "internal"
        if p.startswith(WEB_SCHEMES):
            return "send"
        out["reads"].append(resolve(strip_selector(p), cwd))
        return "read"

    if client == "omp":
        if tool == "read":
            p = str(inp.get("path", ""))
            out["category"] = local_read(p)
            out["summary"] = "read " + p
            out["selector"] = p != strip_selector(p) and not p.endswith(":raw")
        elif tool in ("grep", "glob"):
            spec = str(inp.get("path", "") or ".")
            entries = [s.strip() for s in spec.split(";") if s.strip()]
            out["category"] = "read"
            out["excludes"] = [s[1:] for s in entries if s.startswith("!")]
            for s in entries:
                if not s.startswith("!"):
                    # A wildcard prefix is not an object boundary. Inspect the
                    # nearest concrete ancestor; exclusions cannot prove privacy.
                    concrete = re.split(r"[*?\[]", strip_selector(s), 1)[0]
                    if concrete != strip_selector(s):
                        concrete = os.path.dirname(concrete) or "."
                    out["scans"].append(resolve(concrete or ".", cwd))
            if not out["scans"]:
                out["scans"].append(resolve(".", cwd))
            out["summary"] = "%s %s" % (tool, spec)
        elif tool == "write":
            p = str(inp.get("path", ""))
            if p.startswith("xd://lsp") or p.startswith("xd://report_issue"):
                out["category"] = "internal"
            elif p.startswith("proc://"):
                out["category"] = "exec"
            elif p.startswith(INTERNAL_SCHEMES):
                out["category"] = "internal"
            elif p.startswith("xd://"):
                out["category"] = "exec"
            elif ":" in p:
                # Archives/SQLite/internal selectors are not reversible plain files.
                out["category"] = "exec"
            else:
                out["category"] = "write"
                out["writes"].append(resolve(p, cwd))
            out["summary"] = "write " + p
        elif tool == "edit":
            out["category"] = "write"
            out["writes"] = [resolve(p, cwd) for p in edit_targets(inp.get("input", ""))]
            if any(":" in p for p in edit_targets(inp.get("input", ""))):
                out["category"] = "exec"
            out["summary"] = "edit " + ", ".join(out["writes"])
        elif tool == "bash":
            command = str(inp.get("command", ""))
            out["category"], paths, recursive = classify_bash(command, inp.get("cwd") or cwd)
            (out["scans"] if recursive else out["reads"]).extend(paths)
            out["command"] = command
            if is_scoped_launch(command):
                out["category"] = "delegate"
            out["summary"] = "bash " + command[:300]
        elif tool == "web_search":
            out["category"] = "send"
            out["summary"] = "web_search " + str(inp.get("query", ""))[:300]
        elif tool == "task":
            out["category"] = "delegate"
            out["recipients"] = [{"name": task.get("name"), "agent": task.get("agent"), "task": task.get("task")}
                                 for task in inp.get("tasks", [])]
        elif tool in ("ask", "todo", "wait"):
            out["category"] = "internal"
    else:
        if tool in ("Read", "NotebookRead"):
            p = str(inp.get("file_path") or inp.get("notebook_path") or "")
            out["category"] = local_read(p)
            out["selector"] = bool(inp.get("offset") or inp.get("limit"))
            out["summary"] = "Read " + p
        elif tool in ("Grep", "Glob", "LS"):
            out["category"] = "read"
            out["scans"].append(resolve(str(inp.get("path") or "."), cwd))
            out["summary"] = "%s %s" % (tool, inp.get("path") or ".")
        elif tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            out["category"] = "write"
            out["writes"].append(resolve(str(inp.get("file_path") or inp.get("notebook_path") or ""), cwd))
            out["summary"] = "%s %s" % (tool, out["writes"][0])
        elif tool == "Bash":
            command = str(inp.get("command", ""))
            out["category"], paths, recursive = classify_bash(command, cwd)
            (out["scans"] if recursive else out["reads"]).extend(paths)
            out["command"] = command
            out["summary"] = "Bash " + command[:300]
        elif tool in ("WebFetch", "WebSearch"):
            out["category"] = "send"
            out["summary"] = "%s %s" % (tool, inp.get("url") or inp.get("query") or "")
        elif tool == "Task":
            out["category"] = "delegate"
        elif tool in ("TodoWrite", "ExitPlanMode"):
            out["category"] = "internal"
    return out


# ---------------------------------------------------------------- decision

def private_reader(config, payload):
    # Provider labels supplied by the client are not model identity evidence.
    # This broker has no runtime model attestation; private reads fail closed.
    return False


def is_stop_request(command):
    return bool(re.fullmatch(r"\s*(/usr/bin/python3 -I )?/Library/Governance/gate/gate\.py stop-request [^;&|`$<>()\n]*", command or ""))


def is_scoped_launch(command):
    if re.search(r"[;&|`$<>()\n]", command or ""):
        return False
    try:
        tokens = shlex.split(command)
    except ValueError:
        return False
    return tokens[:4] == ["/usr/bin/python3", "-I", "/Library/Governance/gate/authorization.py", "run"]


def decide(payload, authorize=None):
    """Return (decision, reason, record_fields)."""
    client, tool = payload.get("client"), payload.get("tool")
    index = load_index()
    config, config_id = load_config(index)
    executor = {k: payload.get(k) for k in ("client", "session", "agent", "model", "kernel_executor")}
    if config is None:
        return "deny", "未登记代理动作配置公报，闸门程序无法审查（S2026-002 §3）。依 C2026-001 v1 C3 中止并提请人类主权者。", {"executor": executor}, None
    device, spec = current_device(config)
    if spec is None:
        return "deny", "本机不是登记载明的设备（C2026-001 v1 A4）。", {"executor": executor}, None
    action = classify(client, tool, payload.get("input"), payload.get("cwd"))
    fields = {"device": device, "executor": executor, "action": action, "config": config_id}
    procedure = basis_label(index, "S2026-002", "")

    # §7: the stop flag blocks every action; lighting it is always possible.
    if action["category"] == "exec" and is_stop_request(action.get("command")):
        return "allow", "", dict(fields, basis=[procedure + "§7"]), spec
    if stop_lit(spec):
        return "deny", "停止标志亮起，全部动作暂停（%s§7）。恢复须经人类主权者命令并以系统口令确认。" % procedure, fields, spec

    reads = action["reads"] + action["scans"]
    # §10 and the gate's own state: records, stop flags, state and snapshots are not agent material.
    audit_roots = internal_roots(spec) + ["/Library/Governance/authorization"]
    if any(under(p, audit_roots) for p in reads) or any(contains(p, audit_roots) for p in action["scans"]):
        return "deny", "记录、停止标志与闸门状态只供审计程序与人类主权者读取（%s§10）。" % procedure, fields, spec
    if any(write_protected(spec, p) for p in action["writes"]) or \
            (action["category"] == "exec" and any(p in (action.get("command") or "") for p in ["/Library/Governance", ".omp/", ".claude/settings"] + spec.get("protected", []) + internal_roots(spec))):
        return "deny", "登记、闸门程序、闸门配置与代理启动配置只能经人类主权者以系统口令确认后变更（%s§3）。" % procedure, fields, spec

    # §6: the private scope is open only to the agents the gazette lists.
    private = spec.get("private", [])
    if private and not private_reader(config, payload):
        if any(under(p, private) for p in reads):
            return "deny", "该路径属于公报 %s 列明的私密范围，只供列明的代理读取（%s§6）。" % (config_id, procedure), fields, spec
        if any(contains(p, private) for p in action["scans"]):
            return "deny", "该检索可能进入公报 %s 的私密范围（%s§6）。排除表达式不能证明不会进入；须缩小到明确的非私密路径。" % (config_id, procedure), fields, spec

    # §5 and C2026-001 E1: the laws governing this category are read in this session first.
    session = payload.get("session") or "unknown"
    state = load_state(spec, session)
    register_read = action["category"] == "read" and action["reads"] and all(under(p, [REGISTER]) for p in action["reads"])
    if register_read:
        # Recording happens only after the broker validates a successful full
        # tool result. PreToolUse/permission alone never proves a completed read.
        return "allow", "", dict(fields, basis=[basis_label(index, "S2026-002", "§5")]), spec
    read_paths = {os.path.realpath(path) for path in state["read"]}
    missing = [path for path in required_readings(index, action["category"]) if os.path.realpath(path) not in read_paths]
    if missing:
        return "deny", "执行前须完整读取所依据的法（C2026-001 v1 E1；%s§5）。先逐一完整 read，路径加 :raw（不要范围，须成功返回全部内容）：%s" % (procedure, "，".join(missing)), fields, spec

    # §4: authorization. Reading is authorized by §6; every other action needs a command.
    if action["category"] == "read":
        return "allow", "", dict(fields, basis=[basis_label(index, "S2026-002", "§6")]), spec
    allowed, authorization = authorize(action) if authorize else (False, {"scope_result": "no protected authorization broker"})
    fields.update(authorization)
    if not allowed:
        return "deny", "无可核验的执行者绑定任务授权，或动作/对象超出范围。须本人在 sudo 终端明确授权；界面确认、授权编号、普通文件均不能授权。", fields, spec
    fields["basis"] = [procedure + "§2、§4", "任务授权 " + authorization["authorization"]]
    if action["category"] == "write":
        try:
            if any(os.path.lexists(p) and not os.path.isfile(p) for p in action["writes"]):
                raise OSError("non-regular write target has no reversible file snapshot")
            fields["snapshots"] = [snapshot(spec, session, p) for p in action["writes"] if os.path.isfile(p)]
        except OSError as error:
            fields["snapshot_error"] = str(error)
            if not authorization.get("irreversible_writes"):
                return "deny", "无法建立可逆快照，原授权未明确允许不可逆写入。", fields, spec
    return "allow", "", fields, spec


def record(spec, fields, decision, reason):
    if spec is None:
        return
    entry = dict(fields, at=now(), decision=decision)
    if reason:
        entry["reason"] = reason
    append_line(spec["records"], entry)


# ---------------------------------------------------------------- entry points

def broker_request(message):
    path = os.path.join(os.path.dirname(__file__), "authorization.py")
    module_spec = importlib.util.spec_from_file_location("governance_authorization", path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module.request(message)


def cmd_decide(raw):
    try:
        result = broker_request({"op": "decide", "payload": json.loads(raw)})
    except Exception as error:
        result = {"decision": "deny", "reason": "受保护授权程序不可用，动作已拦下：" + str(error)}
    print(json.dumps(result, ensure_ascii=False))


def cmd_outcome(raw):
    # Retained command name; legacy approved=true cannot mint authorization.
    try:
        payload = json.loads(raw)
        result = broker_request(dict(payload, op="outcome"))
    except Exception as error:
        result = {"recorded": False, "error": str(error)}
    print(json.dumps(result, ensure_ascii=False))


def cmd_claude():
    event = json.loads(sys.stdin.read())
    payload = {"client": "claude", "session": event.get("session_id"), "tool": event.get("tool_name"),
               "input": event.get("tool_input"), "cwd": event.get("cwd"), "agent": None,
               "model": {"provider": "anthropic"}, "interactive": False}
    try:
        result = broker_request({"op": "decide", "payload": payload})
        decision, reason = result["decision"], result.get("reason", "")
    except Exception as e:
        decision, reason = "deny", "闸门程序出错，动作已拦下：%s" % e
    out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": decision}}
    if reason:
        out["hookSpecificOutput"]["permissionDecisionReason"] = reason
    print(json.dumps(out, ensure_ascii=False))


def cmd_stop(source, clear):
    config, _ = load_config(load_index())
    device, spec = current_device(config or {})
    if spec is None:
        sys.exit("本机不是登记载明的设备")
    if clear:
        module_spec = importlib.util.spec_from_file_location("governance_authorization", os.path.join(os.path.dirname(__file__), "authorization.py"))
        authorization = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(authorization)
        path = spec["stop_clears"]
        authorization.protected(path if os.path.lexists(path) else os.path.dirname(path))
        authorization.confirm({"op": "stop-clear", "effect": "clear stop flag; expired/revoked grants remain invalid"})
        append_line(spec["stop_clears"], {"at": now(), "by": os.environ["SUDO_USER"]})
        print("停止标志已熄灭")
    else:
        append_line(spec["stop_requests"], {"at": now(), "source": source})
        print("停止标志已点亮")


def cmd_status():
    print(json.dumps(broker_request({"op": "status"}), ensure_ascii=False, indent=2))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cmd = sys.argv[1]
    if cmd == "decide":
        cmd_decide(sys.argv[2])
    elif cmd == "outcome":
        cmd_outcome(sys.argv[2])
    elif cmd == "claude":
        cmd_claude()
    elif cmd == "stop-request":
        print(json.dumps(broker_request({"op": "stop-request", "source": " ".join(sys.argv[2:]) or "unspecified"}), ensure_ascii=False))
    elif cmd == "stop-clear":
        cmd_stop("", clear=True)
    elif cmd == "status":
        cmd_status()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
