#!/usr/bin/env python3
"""Protected local task authorization. Install root-owned and run with python3 -I.

serve: root LaunchDaemon; grant/revoke/narrow: password-authenticated sudo + tty.
run: nested scoped omp launch, available only inside an already bound executor.
IDs are audit references, never credentials. No environment trust override exists.
"""
import argparse
import ctypes
import hashlib
import codecs
import importlib.util
import json
import io
import os
import pwd
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time

BASE = "/Library/Governance"
SOCKET = BASE + "/run/authorization.sock"
STATE = BASE + "/authorization"
CONFIG = BASE + "/gate/authorization-config.json"
EXTENSION = BASE + "/gate/omp-gate.ts"
MAX_MESSAGE = 16 * 1024 * 1024


def load_gate():
    spec = importlib.util.spec_from_file_location("governance_gate", os.path.join(os.path.dirname(__file__), "gate.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def file_digest(path):
    with open(path, "rb") as stream:
        return hashlib.sha256(stream.read()).hexdigest()


def protected(path, directory=False):
    """Check every ancestor, not just the leaf (also rejects symlinks)."""
    path = os.path.abspath(path)
    current = path
    while True:
        info = os.lstat(current)
        if info.st_uid != 0 or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise PermissionError("unprotected installation: " + current)
        if current == path and directory and not stat.S_ISDIR(info.st_mode):
            raise PermissionError("not a directory: " + current)
        if current == "/":
            return
        current = os.path.dirname(current)


def recv_message(conn):
    data = bytearray()
    while True:
        part = conn.recv(65536)
        if not part:
            raise EOFError("connection closed")
        data.extend(part)
        if len(data) > MAX_MESSAGE:
            raise ValueError("request too large")
        if b"\n" in part:
            line, rest = bytes(data).split(b"\n", 1)
            if rest:
                raise ValueError("one request per connection")
            return json.loads(line)


def send_message(conn, message):
    conn.sendall((canonical(message) + "\n").encode())


def sovereign(message, peer_uid):
    protected(CONFIG)
    with open(CONFIG) as stream:
        config = json.load(stream)
    uid = config["sovereign_uid"]
    if not isinstance(uid, int) or uid <= 0 or pwd.getpwuid(uid).pw_name != config["sovereign_user"]:
        raise PermissionError("invalid installed sovereign identity")
    if peer_uid != 0 or message.get("uid") != uid or message.get("confirmation", {}).get("uid") != uid:
        raise PermissionError("only installed sovereign may confirm authorization")
    return uid


def connect():
    # A fake same-UID server must not be able to authorize a gate call.
    protected(os.path.dirname(SOCKET), directory=True)
    info = os.lstat(SOCKET)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise PermissionError("authorization socket is not root-owned")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(30)
    conn.connect(SOCKET)
    return conn


def request(message):
    with connect() as conn:
        send_message(conn, message)
        result = recv_message(conn)
    if "error" in result:
        raise PermissionError(result["error"])
    return result


def peer_identity(conn):
    if sys.platform == "darwin":
        # SOL_LOCAL / LOCAL_PEERPID, and getpeereid: kernel-authenticated values.
        pid = struct.unpack("i", conn.getsockopt(0, 2, 4))[0]
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid)):
            raise OSError(ctypes.get_errno(), "getpeereid")
        return pid, uid.value
    pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return pid, uid


def process_identity(pid):
    """Return parent, real UID and a non-reusable process birth token."""
    if sys.platform == "darwin":
        class BSDInfo(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint32) for name in
                        ("flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "rfu")]
            _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
            _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid", "nice")]
            _fields_ += [("start_sec", ctypes.c_uint64), ("start_usec", ctypes.c_uint64)]
        value = BSDInfo()
        libc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        size = libc.proc_pidinfo(pid, 3, 0, ctypes.byref(value), ctypes.sizeof(value))
        if size != ctypes.sizeof(value):
            raise ProcessLookupError(pid)
        return value.ppid, value.ruid, (value.start_sec, value.start_usec)
    with open("/proc/%d/stat" % pid) as stream:
        fields = stream.read().rsplit(")", 1)[1].split()
    return int(fields[1]), os.stat("/proc/%d" % pid).st_uid, (int(fields[19]),)


def inside(path, roots):
    path = os.path.realpath(path)
    roots = [os.path.realpath(r) for r in roots]
    return any(path == root or path.startswith(root.rstrip("/") + "/") for root in roots)


def normalize_scope(raw):
    keys = {"original_command", "goal", "expires_at", "actions", "paths", "commands", "operations", "irreversible_writes"}
    if not isinstance(raw, dict) or set(raw) != keys:
        raise ValueError("scope requires exactly: " + ", ".join(sorted(keys)))
    out = json.loads(canonical(raw))
    for key in ("original_command", "goal"):
        if not isinstance(out[key], str) or not out[key].strip():
            raise ValueError("empty " + key)
    if isinstance(out["expires_at"], bool) or not isinstance(out["expires_at"], (int, float)) or not time.time() < out["expires_at"] <= time.time() + 31 * 86400:
        raise ValueError("expiry must be in the next 31 days")
    if not isinstance(out["irreversible_writes"], bool):
        raise ValueError("irreversible_writes must be boolean")
    if not isinstance(out["actions"], list) or any(a not in ("internal", "write", "delegate", "exec", "send") for a in out["actions"]):
        raise ValueError("invalid actions")
    if not isinstance(out["paths"], list) or any(not isinstance(p, str) or not os.path.isabs(p) for p in out["paths"]):
        raise ValueError("paths must be absolute")
    out["paths"] = sorted(set(os.path.realpath(p) for p in out["paths"]))
    if any(inside(p, [BASE]) or inside(BASE, [p]) for p in out["paths"]):
        raise ValueError("scope may not include governance installation")
    if not isinstance(out["commands"], list) or not isinstance(out["operations"], list):
        raise ValueError("commands and operations must be arrays")
    for entry in out["commands"]:
        if set(entry) != {"command", "cwd", "irreversible"} or entry["irreversible"] is not True or not isinstance(entry["command"], str) or not os.path.isabs(entry["cwd"]):
            raise ValueError("commands require exact command/cwd and irreversible:true")
        entry["cwd"] = os.path.realpath(entry["cwd"])
        if not inside(entry["cwd"], out["paths"]):
            raise ValueError("command cwd outside paths")
    for entry in out["operations"]:
        if set(entry) != {"tool", "input", "irreversible"} or entry["irreversible"] is not True or not isinstance(entry["tool"], str):
            raise ValueError("operations require exact tool/input and irreversible:true")
    return out


def subset(child, parent):
    return (child["expires_at"] <= parent["expires_at"] and
            child["original_command"] == parent["original_command"] and
            set(child["actions"]) <= set(parent["actions"]) and
            all(inside(p, parent["paths"]) for p in child["paths"]) and
            all(c in parent["commands"] for c in child["commands"]) and
            all(c in parent["operations"] for c in child["operations"]) and
            (not child["irreversible_writes"] or parent["irreversible_writes"]))


def scope_allows(scope, action, payload):
    category = action["category"]
    if category not in scope["actions"]:
        return False, "action category outside task scope"
    if category in ("internal", "delegate"):
        return True, "category authorized"
    if category == "write":
        paths = action["writes"]
        return bool(paths) and all(inside(p, scope["paths"]) for p in paths), "write path scope"
    if category == "exec" and "command" in action:
        candidate = {"command": action["command"], "cwd": os.path.realpath((payload.get("input") or {}).get("cwd") or payload.get("cwd") or "."), "irreversible": True}
        allowed = [dict(entry, cwd=os.path.realpath(entry["cwd"])) for entry in scope["commands"]]
        return candidate in allowed, "exact explicitly irreversible command scope"
    candidate = {"tool": payload.get("tool"), "input": payload.get("input"), "irreversible": True}
    return candidate in scope["operations"], "exact explicitly irreversible operation scope"


class Broker:
    def __init__(self, directory=STATE):
        self.directory = directory
        self.gate = load_gate()
        registered_device = self.gate.current_device
        def protected_device(config):
            device, spec = registered_device(config)
            if spec is not None:
                for key in ("records", "stop_requests", "stop_clears", "state", "snapshots"):
                    path = spec[key]
                    if not os.path.isabs(path):
                        raise PermissionError("relative mutable gate path")
                    protected(path if os.path.lexists(path) else os.path.dirname(path),
                              directory=key in ("state", "snapshots") or not os.path.lexists(path))
            return device, spec
        self.gate.current_device = protected_device
        self.lock = threading.RLock()
        self.records = {}
        self.processes = {}
        self.pending = {}
        self.shutdown = threading.Event()
        # Restart invalidates all old bindings, even if a PID is recycled.
        self.boot = secrets.token_hex(16)
        for name in os.listdir(directory):
            if name.endswith(".json"):
                with open(os.path.join(directory, name)) as stream:
                    item = json.load(stream)
                if item.get("status") == "active":
                    bound = item.get("executor", {})
                    try:
                        if tuple(bound.get("birth", [])) == process_identity(bound["pid"])[2]:
                            os.killpg(bound["pid"], signal.SIGKILL)
                    except (KeyError, ProcessLookupError):
                        pass
                    item["status"] = "broker-restarted"
                    self.persist(item)
                self.records[item["id"]] = item

    def audit(self, event, **fields):
        self.gate.append_line(os.path.join(self.directory, "audit.jsonl"), dict(at=self.gate.now(), event=event, **fields))

    def persist(self, item):
        path = os.path.join(self.directory, item["id"] + ".json")
        temporary = path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(item, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    def chain(self, item):
        chain = [item]
        while chain[-1].get("parent"):
            chain.append(self.records[chain[-1]["parent"]])
        return list(reversed(chain))

    def valid(self, item):
        return all(a["status"] == "active" and a["scope"]["expires_at"] > time.time() for a in self.chain(item))

    def binding(self, pid, uid):
        seen = set()
        while pid > 1 and pid not in seen:
            seen.add(pid)
            parent, owner, birth = process_identity(pid)
            if owner != uid:
                return None
            for item in self.records.values():
                bound = item.get("executor", {})
                if bound.get("pid") == pid and tuple(bound.get("birth", [])) == birth and item.get("boot") == self.boot:
                    return item
            pid = parent
        return None

    def stopped(self):
        config, _ = self.gate.load_config(self.gate.load_index())
        _, spec = self.gate.current_device(config or {})
        return spec is None or self.gate.stop_lit(spec)

    def terminate(self, item, reason):
        item["status"] = reason
        self.persist(item)
        proc = self.processes.get(item["id"])
        if proc is not None:
            descendants = []
            try:
                listing = subprocess.run(["/bin/ps", "-axo", "pid="], stdout=subprocess.PIPE,
                                         stderr=subprocess.DEVNULL, check=True,
                                         env={"PATH": "/usr/bin:/bin"}, timeout=5)
                for value in listing.stdout.split():
                    candidate = int(value)
                    try:
                        owner = process_identity(candidate)
                        if owner[1] != item["uid"]:
                            continue
                        bound = self.binding(candidate, item["uid"])
                        if bound and item in self.chain(bound):
                            descendants.append((candidate, owner[2]))
                    except ProcessLookupError:
                        continue
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                self.audit("interrupt-enumeration-failed", authorization=item["id"], error=str(error))
            # The unreaped Popen process reserves this PID, preventing group-ID reuse.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
                self.audit("interrupt", authorization=item["id"], signal="SIGKILL", reason=reason,
                           limitation="uninterruptible kernel IO or detached descendants may finish; later gated actions denied")
            except ProcessLookupError:
                pass
            # Tool runners can put children in their own process groups. Capture
            # descendants before killing the executor, then match birth tokens.
            for pid, birth in descendants:
                try:
                    if process_identity(pid)[2] == birth:
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def monitor(self):
        while not self.shutdown.wait(0.2):
            with self.lock:
                self.pending = {key: value for key, value in self.pending.items() if value["expires"] > time.time()}
                try:
                    stopped = self.stopped()
                except Exception:
                    stopped = True
                for item in list(self.records.values()):
                    if item["status"] == "active" and (stopped or not self.valid(item)):
                        self.terminate(item, "stopped" if stopped else "expired-or-parent-invalid")

    def authorize(self, item, action, payload):
        if item is None or not self.valid(item):
            return False, {"scope_result": "no live kernel-bound executor"}
        checks = [scope_allows(a["scope"], action, payload) for a in self.chain(item)]
        allowed = all(result[0] for result in checks)
        return allowed, {"authorization": item["id"], "original_authorization": self.chain(item)[0]["id"],
                         "delegation_chain": [a["id"] for a in self.chain(item)],
                         "scope_result": checks, "irreversible_writes": all(a["scope"]["irreversible_writes"] for a in self.chain(item))}

    def decide(self, payload, pid, uid):
        item = self.binding(pid, uid)
        # An invalid launched executor cannot fall back to law-only execution.
        if item is not None and not self.valid(item):
            self.audit("deny", pid=pid, uid=uid, authorization=item["id"], reason="authorization invalid")
            return {"decision": "deny", "reason": "任务授权已失效；下级及后续动作停止。"}
        parent, _, birth = process_identity(pid)
        parent_birth = process_identity(parent)[2]
        identity = "%s:%s:%s:%s" % (uid, pid, parent, parent_birth)
        if item:
            identity = item["id"]
        payload = dict(payload)
        # User labels aid tracing, but never participate in executor authentication.
        payload["session"] = identity + ":" + str(payload.get("session", "unknown"))
        payload["kernel_executor"] = {"pid": pid, "uid": uid, "birth": birth}
        decision, reason, fields, spec = self.gate.decide(payload, lambda action: self.authorize(item, action, payload))
        if item is not None and "authorization" not in fields:
            fields.update(authorization=item["id"], original_authorization=self.chain(item)[0]["id"],
                          delegation_chain=[a["id"] for a in self.chain(item)],
                          scope_result="law-authorized read; task adds no private-read permission")
        self.gate.record(spec, fields, decision, reason)
        result = {"decision": decision, "reason": reason}
        action = fields.get("action", {})
        if decision == "allow" and action.get("category") == "read" and action.get("reads") and not action.get("selector") and payload.get("tool") in ("read", "Read"):
            paths = action["reads"]
            if all(inside(p, [self.gate.REGISTER]) and os.path.isfile(p) for p in paths):
                receipt = secrets.token_hex(24)
                self.pending[receipt] = {"identity": identity, "session": payload["session"], "paths": paths,
                                         "spec": spec, "expires": time.time() + 120,
                                         "digests": [file_digest(p) for p in paths]}
                result["read_receipt"] = receipt
        return result

    def outcome(self, message, pid, uid):
        receipt = self.pending.pop(message.get("read_receipt"), None)
        if not receipt or receipt["expires"] < time.time():
            raise PermissionError("missing or expired read receipt")
        item = self.binding(pid, uid)
        parent, _, _ = process_identity(pid)
        identity = item["id"] if item else "%s:%s:%s:%s" % (uid, pid, parent, process_identity(parent)[2])
        if identity != receipt["identity"] or (item and not self.valid(item)) or self.stopped():
            raise PermissionError("read receipt executor mismatch or stopped")
        text = message.get("text", "")
        if message.get("is_error") is not False or not isinstance(text, str):
            raise ValueError("failed read does not satisfy law reading")
        for path, digest in zip(receipt["paths"], receipt["digests"]):
            with open(path, encoding="utf-8") as stream:
                full = stream.read()
            if hashlib.sha256(full.encode()).hexdigest() != digest or full.strip() not in text:
                raise ValueError("read was truncated, transformed, or law changed; use :raw full read")
        state = self.gate.load_state(receipt["spec"], receipt["session"])
        state["read"] = sorted(set(state["read"]) | set(receipt["paths"]))
        self.gate.save_state(receipt["spec"], receipt["session"], state)
        self.audit("law-read-completed", executor=identity, paths=receipt["paths"])
        return {"recorded": True}

    def create(self, message, uid, parent=None):
        scope = normalize_scope(message["scope"])
        if self.stopped():
            raise PermissionError("stop flag is lit or configuration unavailable")
        if parent and (not self.valid(parent) or "delegate" not in parent["scope"]["actions"] or not subset(scope, parent["scope"])):
            raise PermissionError("delegation exceeds live parent scope")
        if uid == 0:
            raise PermissionError("executor may not run as root")
        if not isinstance(message.get("prompt"), str) or not message["prompt"].strip():
            raise ValueError("prompt required")
        cwd = os.path.realpath(message["cwd"])
        if not inside(cwd, scope["paths"]):
            raise PermissionError("launch cwd outside scope")
        item = {"id": secrets.token_hex(16), "parent": parent["id"] if parent else None, "scope": scope,
                "uid": uid, "status": "active", "created_at": self.gate.now(), "boot": self.boot,
                "launch": {"prompt": message["prompt"], "cwd": cwd, "model": message.get("model")},
                "confirmation": message.get("confirmation") if not parent else self.chain(parent)[0]["confirmation"]}
        self.records[item["id"]] = item
        self.persist(item)
        return item

    def launch(self, item):
        protected(CONFIG)
        protected(EXTENSION)
        with open(CONFIG) as stream:
            config = json.load(stream)
        executable = config["omp"]
        protected(executable)
        account = pwd.getpwuid(item["uid"])
        launch = item["launch"]
        argv = [executable, "--trusted-extension", EXTENSION, "-p", "--no-session", "--no-pty"]
        if launch.get("model"):
            argv += ["--model", launch["model"]]
        # Prompt beginning with '-' must not become an option; '@' file expansion
        # would let file contents replace the human-confirmed command.
        prompt = launch["prompt"]
        if prompt.startswith(("-", "@")):
            raise ValueError("prompt may not begin with '-' or '@'")
        argv.append(prompt)
        environment = {"HOME": account.pw_dir, "USER": account.pw_name, "LOGNAME": account.pw_name,
                       "PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin", "LANG": "en_US.UTF-8"}
        # Use a protected Python trampoline, not preexec_fn in this threaded daemon.
        trampoline = os.path.join(os.path.dirname(__file__), "executor.py")
        protected(trampoline)
        proc = subprocess.Popen(["/usr/bin/python3", "-I", trampoline, str(item["uid"]), launch["cwd"]] + argv,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                env=environment, start_new_session=True)
        try:
            # Trampoline blocks before setuid/exec; broker installs binding first.
            birth = process_identity(proc.pid)[2]
            item["executor"] = {"pid": proc.pid, "birth": birth, "uid": item["uid"], "argv": argv}
            self.processes[item["id"]] = proc
            self.persist(item)
            self.audit("launch", authorization=item["id"], parent=item["parent"], executor=item["executor"])
            proc.stdin.write(b"G")
            proc.stdin.close()
        except Exception:
            proc.kill()
            proc.wait()
            raise
        return proc

    def handle(self, conn):
        launched = None
        try:
            pid, uid = peer_identity(conn)
            conn.settimeout(30)
            message = recv_message(conn)
            operation = message.get("op")
            with self.lock:
                if operation == "decide":
                    result = self.decide(message["payload"], pid, uid)
                elif operation == "outcome":
                    result = self.outcome(message, pid, uid)
                elif operation == "stop-request":
                    self.gate.cmd_stop("broker peer uid=%d pid=%d: %s" % (uid, pid, str(message.get("source", ""))[:500]), False)
                    for active in list(self.records.values()):
                        if active["status"] == "active":
                            self.terminate(active, "stopped")
                    result = {"stopped": True}
                elif operation == "status":
                    index = self.gate.load_index()
                    config, config_id = self.gate.load_config(index)
                    device, spec = self.gate.current_device(config or {})
                    result = {"config": config_id, "device": device, "stop_lit": self.gate.stop_lit(spec) if spec else None,
                              "required_readings": self.gate.required_readings(index, "write")}
                elif operation in ("grant", "run"):
                    if operation == "grant":
                        executor_uid = sovereign(message, uid)
                        item = self.create(message, executor_uid)
                    else:
                        parent = self.binding(pid, uid)
                        if parent is None:
                            raise PermissionError("run requires bound executor, not an authorization ID")
                        item = self.create(message, uid, parent)
                    try:
                        launched = self.launch(item)
                    except Exception:
                        self.terminate(item, "launch-failed")
                        raise
                    result = {"authorization": item["id"], "started": True}
                elif operation in ("revoke", "narrow"):
                    sovereign(message, uid)
                    item = self.records[message["id"]]
                    if operation == "narrow":
                        scope = normalize_scope(message["scope"])
                        if not subset(scope, item["scope"]):
                            raise PermissionError("narrow cannot expand authorization")
                        item["scope"] = scope
                    # Narrowing invalidates running executors: cannot safely identify an
                    # already-running action's effects. Human may grant a narrower run.
                    for child in list(self.records.values()):
                        if item in self.chain(child) and child["status"] == "active":
                            self.terminate(child, "revoked" if operation == "revoke" else "scope-narrowed")
                    self.audit(operation, authorization=item["id"], confirmation=message["confirmation"])
                    result = {"changed": True}
                else:
                    raise ValueError("unknown broker operation")
            send_message(conn, result)
            if launched is not None:
                conn.settimeout(None)
                decoder = codecs.getincrementaldecoder("utf-8")("replace")
                while True:
                    chunk = os.read(launched.stdout.fileno(), 8192)
                    text = decoder.decode(chunk, final=not chunk)
                    if text:
                        send_message(conn, {"output": text})
                    if not chunk:
                        break
                with self.lock:
                    try:
                        os.killpg(launched.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    code = launched.wait()
                    if item["status"] == "active":
                        item["status"] = "completed"
                        self.persist(item)
                    self.processes.pop(item["id"], None)
                    for child in list(self.records.values()):
                        if child is not item and item in self.chain(child) and child["status"] == "active":
                            self.terminate(child, "parent-completed")
                    self.audit("exit", authorization=item["id"], code=code)
                send_message(conn, {"exit_code": code})
        except Exception as error:
            with self.lock:
                self.audit("request-error", error=str(error))
                if launched is not None:
                    self.terminate(item, "launcher-disconnected-or-error")
                    launched.wait()
                    self.processes.pop(item["id"], None)
            try:
                send_message(conn, {"error": str(error)})
            except OSError:
                pass
        finally:
            conn.close()


def serve():
    if os.geteuid() != 0:
        raise PermissionError("broker must run as root")
    os.umask(0o077)
    protected(STATE, directory=True)
    protected(os.path.dirname(SOCKET), directory=True)
    protected(os.path.dirname(__file__), directory=True)
    protected(__file__)
    protected(os.path.join(os.path.dirname(__file__), "gate.py"))
    # A second daemon must not replace a live broker's socket.
    import fcntl
    lock = open(os.path.join(STATE, "broker.lock"), "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    broker = Broker()
    if os.path.lexists(SOCKET):
        os.unlink(SOCKET)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(SOCKET)
    os.chmod(SOCKET, 0o666)  # peer credentials authorize requests, never socket possession
    listener.listen(32)
    threading.Thread(target=broker.monitor, daemon=True).start()
    while True:
        conn, _ = listener.accept()
        threading.Thread(target=broker.handle, args=(conn,), daemon=True).start()


def confirm(message):
    if os.geteuid() != 0 or not os.environ.get("SUDO_UID") or int(os.environ["SUDO_UID"]) == 0:
        raise PermissionError("use password-authenticated sudo -k from the human terminal")
    # Validate configured sovereign before displaying any confirmation prompt.
    sovereign({"uid": int(os.environ["SUDO_UID"]), "confirmation": {"uid": int(os.environ["SUDO_UID"])}}, 0)
    token = secrets.token_hex(4)
    # /dev/tty is not seekable. Python 3.9 rejects text-mode line buffering on it.
    raw = io.FileIO(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY), "r+")
    tty = io.TextIOWrapper(raw, encoding="utf-8", write_through=True)
    try:
        tty.write("\n确认以下完整任务授权（不是公报登记）：\n" + json.dumps(message, ensure_ascii=False, indent=2) + "\n输入 CONFIRM " + token + "：")
        if tty.readline().strip() != "CONFIRM " + token:
            raise PermissionError("not confirmed")
    finally:
        tty.close()
    return {"method": "sudo-password-and-terminal-confirmation", "uid": int(os.environ["SUDO_UID"]),
            "at": time.time(), "reference": secrets.token_hex(16),
            "scope_sha256": hashlib.sha256(canonical(message).encode()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("serve", "grant", "run", "revoke", "narrow"))
    parser.add_argument("id", nargs="?")
    parser.add_argument("--scope")
    parser.add_argument("--prompt")
    parser.add_argument("--cwd")
    parser.add_argument("--model")
    args = parser.parse_args()
    if args.command == "serve":
        serve()
        return
    message = {"op": args.command}
    if args.command in ("grant", "run", "narrow"):
        if not args.scope:
            parser.error("--scope is required")
        with open(args.scope, encoding="utf-8") as stream:
            message["scope"] = normalize_scope(json.load(stream))
    if args.command in ("grant", "run"):
        if not args.prompt or not args.cwd:
            parser.error("--prompt and --cwd are required")
        message.update(prompt=args.prompt, cwd=os.path.realpath(args.cwd), model=args.model)
    else:
        if not args.id:
            parser.error("authorization ID is required")
        message["id"] = args.id
    if args.command != "run":
        message["confirmation"] = confirm(message)
        message["uid"] = int(os.environ["SUDO_UID"])
    with connect() as conn:
        conn.settimeout(None)
        send_message(conn, message)
        # Persistent framing for multiple output messages (recv_message is one-shot).
        with conn.makefile("r", encoding="utf-8") as stream:
            for line in stream:
                result = json.loads(line)
                if "error" in result:
                    raise PermissionError(result["error"])
                if "output" in result:
                    print(result["output"], end="", flush=True)
                elif "exit_code" in result:
                    return result["exit_code"] if result["exit_code"] >= 0 else 128 - result["exit_code"]
                else:
                    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, PermissionError) as exc:
        sys.exit("authorization denied: " + str(exc))
