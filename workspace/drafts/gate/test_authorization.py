#!/usr/bin/env python3
"""Isolated regression tests; no sudo, installed writes, or production trust bypass.
Run: /usr/bin/python3 -I governance/drafts/gate/test_authorization.py
"""
import copy
import importlib.util
import json
import os
import socket
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("authorization_test_subject", os.path.join(HERE, "authorization.py"))
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)


def scope(root):
    return {"original_command": "test-only human authorization fixture", "goal": "isolated regression",
            "expires_at": time.time() + 600, "actions": ["internal", "write", "delegate", "exec"],
            "paths": [root], "commands": [], "operations": [], "irreversible_writes": False}


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="gate-unit-")
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        self.scope = auth.normalize_scope(scope(self.root))
        self.broker = auth.Broker(self.root)
        self.gate = self.broker.gate
        self.spec = {"state": self.root + "/state", "snapshots": self.root + "/snapshots",
                     "records": self.root + "/audit/device/records.jsonl",
                     "stop_requests": self.root + "/stop/requests.jsonl", "stop_clears": self.root + "/stop/clears.jsonl",
                     "private": [self.root + "/private"], "protected": []}
        for path in (self.spec["state"], self.spec["snapshots"], os.path.dirname(self.spec["records"]), os.path.dirname(self.spec["stop_requests"])):
            os.makedirs(path)
        self.gate.load_index = lambda: []
        self.gate.load_config = lambda index: ({}, "test-config")
        self.gate.current_device = lambda config: ("test", self.spec)
        self.gate.REGISTER = self.root + "/register"
        os.makedirs(self.gate.REGISTER)
        self.law = self.gate.REGISTER + "/law.md"
        with open(self.law, "w") as stream:
            stream.write("# Test law\n\nComplete body.\n")
        self.payload = {"client": "omp", "session": "fixture-session", "model": {"provider": "ollama"}, "cwd": self.root}

    def fixture_item(self, item_id="fixture", parent=None):
        item = {"id": item_id, "parent": parent, "status": "active", "scope": copy.deepcopy(self.scope),
                "boot": self.broker.boot, "executor": {"pid": 20, "birth": [123], "uid": 501}}
        self.broker.records[item_id] = item
        return item

    def test_scope_rejects_expansion(self):
        child = copy.deepcopy(self.scope)
        child["paths"] = [os.path.dirname(self.root)]
        self.assertFalse(auth.subset(child, self.scope))
        child = copy.deepcopy(self.scope)
        child["expires_at"] += 1
        self.assertFalse(auth.subset(child, self.scope))
        child = copy.deepcopy(self.scope)
        child["irreversible_writes"] = True
        self.assertFalse(auth.subset(child, self.scope))

    def test_command_exact_not_prefix(self):
        self.scope["commands"] = [{"command": "printf safe", "cwd": self.root, "irreversible": True}]
        self.assertTrue(auth.scope_allows(self.scope, {"category": "exec", "command": "printf safe"}, self.payload)[0])
        self.assertFalse(auth.scope_allows(self.scope, {"category": "exec", "command": "printf safe; rm file"}, self.payload)[0])

    def test_symlink_outside_write_scope(self):
        os.symlink("/etc", self.root + "/outside")
        self.assertFalse(auth.scope_allows(self.scope, {"category": "write", "writes": [self.root + "/outside/passwd"]}, self.payload)[0])

    def test_pid_birth_and_owner_bind_not_id(self):
        item = self.fixture_item()
        with mock.patch.object(auth, "process_identity", side_effect=lambda pid: {30: (20, 501, (456,)), 20: (1, 501, (123,))}[pid]):
            self.assertIs(self.broker.binding(30, 501), item)
            self.assertIsNone(self.broker.binding(30, 502))
        with mock.patch.object(auth, "process_identity", return_value=(1, 501, (999,))):
            self.assertIsNone(self.broker.binding(20, 501))

    def test_nested_revocation_and_expiry(self):
        root = self.fixture_item("root")
        child = self.fixture_item("child", "root")
        grandchild = self.fixture_item("grandchild", "child")
        self.assertTrue(self.broker.valid(grandchild))
        root["status"] = "revoked"
        self.assertFalse(self.broker.valid(grandchild))
        root["status"] = "active"
        root["scope"]["expires_at"] = time.time() - 1
        self.assertFalse(self.broker.valid(child))

    def test_interactive_and_bearer_id_not_authorization(self):
        payload = dict(self.payload, tool="todo", input={}, interactive=True, authorization="fixture")
        self.assertEqual(self.gate.decide(payload)[0], "deny")
        payload["client"] = "claude"
        payload["tool"] = "TodoWrite"
        self.assertEqual(self.gate.decide(payload)[0], "deny")

    def test_private_provider_and_exclusion_spoofs(self):
        payload = dict(self.payload, tool="read", input={"path": self.root + "/private/secret"})
        self.assertEqual(self.gate.decide(payload)[0], "deny")
        payload.update(tool="glob", input={"path": self.root + "/**;!**/private-NOT-PRIVATE/**"})
        self.assertEqual(self.gate.decide(payload)[0], "deny")

    def test_stop_equal_time_fails_closed(self):
        for key in ("stop_requests", "stop_clears"):
            self.gate.append_line(self.spec[key], {"at": "2026-11-07T12:00:00.000000+00:00"})
        self.assertTrue(self.gate.stop_lit(self.spec))

    def test_shell_read_allowlist_removed(self):
        self.assertEqual(self.gate.classify_bash("git branch -D valuable", self.root)[0], "exec")
        self.assertEqual(self.gate.classify_bash("cat file", self.root)[0], "exec")

    def test_edit_move_destination_scoped(self):
        targets = self.gate.edit_targets("*** Begin Patch\n[file#ABCD]\nMV /outside/new\n*** End Patch\n")
        self.assertEqual(targets, ["file", "/outside/new"])

    def test_law_read_requires_completed_full_result(self):
        self.gate.required_readings = lambda index, category: [self.law]
        pid, uid = os.getpid(), os.getuid()
        payload = dict(self.payload, tool="read", input={"path": self.law + ":raw"})
        result = self.broker.decide(payload, pid, uid)
        self.assertEqual(result["decision"], "allow")
        receipt = result["read_receipt"]
        with self.assertRaises(ValueError):
            self.broker.outcome({"read_receipt": receipt, "is_error": False, "text": "# Test law"}, pid, uid)
        result = self.broker.decide(payload, pid, uid)
        with open(self.law) as stream:
            text = stream.read()
        self.assertTrue(self.broker.outcome({"read_receipt": result["read_receipt"], "is_error": False, "text": text}, pid, uid)["recorded"])
        ordinary = dict(self.payload, tool="read", input={"path": self.root + "/ordinary"})
        self.assertEqual(self.broker.decide(ordinary, pid, uid)["decision"], "allow")

    def test_unprotected_sink_is_rejected(self):
        broker = auth.Broker(self.root)
        with mock.patch.object(auth, "protected", side_effect=PermissionError("unprotected sink")):
            with mock.patch.object(broker.gate.socket, "gethostname", return_value="test"):
                with self.assertRaises(PermissionError):
                    broker.gate.current_device({"devices": {"test": dict(self.spec, hostname="test")}})

    def test_socket_credentials_are_kernel_identity(self):
        left, right = socket.socketpair()
        try:
            pid, uid = auth.peer_identity(left)
            self.assertEqual((pid, uid), (os.getpid(), os.getuid()))
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
