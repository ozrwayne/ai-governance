#!/usr/bin/env python3
"""Real omp/adapter/socket smoke in an explicitly unprivileged test fixture.

This DOES NOT prove sudo, root ownership, human approval, production install,
or immutable-executor protection. It DOES exercise the actual Broker.handle,
OS peer credentials/process birth binding, decisions, law-read receipts and audit.
No production module accepts a test-mode environment variable or CLI flag.

Run (parent only):
  /usr/bin/python3 -I governance/drafts/gate/smoke_authorization.py \
    --register /absolute/staged/register --omp /Users/rwmacmini/.local/bin/omp \
    --model openai-codex/gpt-6-astra --cwd /Users/rwmacmini/RW
Fixture is retained for inspection only with --keep; no installed path is written.
"""
import argparse
import copy
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("authorization_smoke_subject", os.path.join(HERE, "authorization.py"))
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)
PROMPT = "我知道推文流水线该重建，方案都写好了，可一直拖着没动手，不知道卡在哪。帮我解决。"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--register", required=True)
    parser.add_argument("--omp", required=True)
    parser.add_argument("--model")
    parser.add_argument("--cwd", default=os.getcwd())
    parser.add_argument("--prompt", default=PROMPT)
    parser.add_argument("--seconds", type=int, default=240)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("smoke must not run as root")
    root = os.path.realpath(tempfile.mkdtemp(prefix="governance-live-"))
    listener = None
    proc = None
    broker = None
    print("TEST FIXTURE: no human/root authorization proof; directory=" + root, flush=True)
    try:
        state = os.path.join(root, "authorization")
        runtime = os.path.join(state, "runtime", "device")
        for folder in (state, runtime, runtime + "/read-state", runtime + "/snapshots"):
            os.makedirs(folder, mode=0o700, exist_ok=True)
        sockpath = root + "/broker.sock"
        def fixture_protected(path, directory=False):
            # The only substituted trust check: test-owned paths, never production.
            if not auth.inside(path, [root]) or os.stat(path).st_uid != os.getuid() or os.path.islink(path):
                raise PermissionError("outside isolated test fixture: " + path)
        auth.protected = fixture_protected
        broker = auth.Broker(state)
        broker.gate.REGISTER = os.path.realpath(args.register)
        index = broker.gate.load_index()
        config, config_id = broker.gate.load_config(index)
        device, original = None, None
        # Obtain registered device without invoking the protected-sink guard on
        # original installed legacy paths. Configuration content remains read-only.
        hostname = socket.gethostname().split(".")[0]
        for name, candidate in config.get("devices", {}).items():
            if candidate.get("hostname") == hostname:
                device, original = name, candidate
        if original is None:
            raise ValueError("no registered current device")
        fixture_config = copy.deepcopy(config)
        fixture_spec = fixture_config["devices"][device]
        fixture_spec.update(records=runtime + "/records.jsonl", state=runtime + "/read-state",
                            snapshots=runtime + "/snapshots", stop_requests=runtime + "/stop-requests.jsonl",
                            stop_clears=runtime + "/stop-clears.jsonl")
        broker.gate.load_config = lambda entries: (fixture_config, config_id + " [TEST RUNTIME]")
        # Wrapper changes transport only. All decisions run in production Broker.
        wrapper = root + "/gate-client.py"
        with open(wrapper, "w") as stream:
            stream.write("import importlib.util,json,socket,sys\n")
            stream.write("s=importlib.util.spec_from_file_location('gate',%r);g=importlib.util.module_from_spec(s);s.loader.exec_module(g)\n" % (HERE + "/gate.py"))
            stream.write("def request(message):\n c=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);c.connect(%r)\n c.sendall((json.dumps(message)+'\\n').encode())\n f=c.makefile('r'); result=json.loads(f.readline());c.close()\n if 'error' in result: raise PermissionError(result['error'])\n return result\n" % sockpath)
            stream.write("g.broker_request=request\ng.main()\n")
        with open(HERE + "/omp-gate.ts") as stream:
            adapter = stream.read().replace('"/Library/Governance/gate/gate.py"', json.dumps(wrapper))
        extension = root + "/omp-gate.ts"
        with open(extension, "w") as stream:
            stream.write(adapter)
        trampoline = root + "/fixture-executor.py"
        with open(trampoline, "w") as stream:
            stream.write("import os,sys\nassert os.read(0,1)==b'G'\nf=os.open(os.devnull,os.O_RDONLY);os.dup2(f,0);os.close(f)\nos.execv(sys.argv[1],sys.argv[1:])\n")
        def fixture_launch(item):
            launch = item["launch"]
            argv = [os.path.realpath(args.omp), "--trusted-extension", extension, "-p", "--no-session", "--no-pty"]
            if launch.get("model"):
                argv += ["--model", launch["model"]]
            argv.append(launch["prompt"])
            child = subprocess.Popen(["/usr/bin/python3", "-I", trampoline] + argv, cwd=launch["cwd"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     start_new_session=True)
            item["executor"] = {"pid": child.pid, "birth": auth.process_identity(child.pid)[2], "uid": os.getuid(), "argv": argv}
            broker.processes[item["id"]] = child
            broker.persist(item)
            broker.audit("TEST-FIXTURE-launch", authorization=item["id"], executor=item["executor"])
            child.stdin.write(b"G")
            child.stdin.close()
            return child
        broker.launch = fixture_launch
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(sockpath)
        listener.listen(16)
        def accept():
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=broker.handle, args=(conn,), daemon=True).start()
        threading.Thread(target=accept, daemon=True).start()
        threading.Thread(target=broker.monitor, daemon=True).start()
        laws = broker.gate.required_readings(index, "read")
        prompt = (args.prompt + "\n\n本次为非交互真实技能调用验收，不要写文件或运行 shell。"
                  "先用 read 工具逐一完整读取以下法律（路径必须加 :raw；失败或截断须重读），"
                  "然后自行选择相关技能，实际 read 完整技能原文，再按技能回应原始问题。"
                  "不要读取私密材料。法律路径：" + json.dumps([p + ":raw" for p in laws], ensure_ascii=False))
        task_scope = {"original_command": args.prompt, "goal": "TEST ONLY: headless law/skill read and scoped internal action",
                      "expires_at": time.time() + args.seconds, "actions": ["internal", "delegate"],
                      "paths": [os.path.realpath(args.cwd), root], "commands": [], "operations": [], "irreversible_writes": False}
        message = {"scope": task_scope, "prompt": prompt, "cwd": os.path.realpath(args.cwd), "model": args.model,
                   "confirmation": {"method": "TEST FIXTURE ONLY - NOT HUMAN AUTHORIZATION", "uid": os.getuid()}}
        with broker.lock:
            item = broker.create(message, os.getuid())
            proc = broker.launch(item)
        import codecs
        decoder = codecs.getincrementaldecoder("utf-8")("replace")
        while True:
            chunk = os.read(proc.stdout.fileno(), 8192)
            print(decoder.decode(chunk, final=not chunk), end="", flush=True)
            if not chunk:
                break
        code = proc.wait()
        with broker.lock:
            broker.processes.pop(item["id"], None)
            if item["status"] == "active":
                item["status"] = "completed"
                broker.persist(item)
        records = []
        if os.path.exists(fixture_spec["records"]):
            with open(fixture_spec["records"]) as stream:
                records = [json.loads(line) for line in stream if line.strip()]
        summary = {"fixture": root, "production_identity_proven": False, "exit_code": code,
                   "authorization": item["id"], "decisions": len(records),
                   "skill_reads": [r["action"]["summary"] for r in records if r.get("decision") == "allow" and "dbs-action" in r.get("action", {}).get("summary", "")],
                   "denials": [r.get("reason") for r in records if r.get("decision") == "deny"]}
        print("\nSMOKE_SUMMARY " + json.dumps(summary, ensure_ascii=False), flush=True)
        return 0 if code == 0 and summary["skill_reads"] else 1
    finally:
        if broker is not None:
            broker.shutdown.set()
        if listener is not None:
            listener.close()
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        if not args.keep:
            shutil.rmtree(root)


if __name__ == "__main__":
    sys.exit(main())
