#!/usr/bin/env python3
"""Isolated registration tests; fixtures explicitly carry test-only provenance.

Run: /usr/bin/python3 -I governance/drafts/tools/test_register.py
Focused temporary-registry smoke:
  /usr/bin/python3 -I governance/drafts/tools/test_register.py RegistrationTests.test_approved_amendment_transaction
No test writes /Library/Governance or asks for sudo.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import multiprocessing
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
DRAFTS = HERE.parent
SPEC = importlib.util.spec_from_file_location("draft_register", HERE / "register.py")
register = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(register)
TARGET = "S2026-002"
TITLE = "代理动作程序法"
AMENDMENT = DRAFTS / "S-agent-procedure-amendment" / "asmade.md"
STATEMENT = DRAFTS / "S-agent-procedure-amendment" / "statement.md"


def fixture_confirmation(note):
    return {"via": "test-only", "user": "isolated-fixture", "note": note}


def fixture_confirm(sources):
    return {label: src if isinstance(src, bytes) else Path(src).read_bytes()
            for label, src in sources if src}


@contextlib.contextmanager
def fixture_authority():
    # These test-local patches are not a production authorization mechanism.
    with mock.patch.object(register, "require_sudo"), \
            mock.patch.object(register, "confirm", side_effect=fixture_confirm) as confirm, \
            mock.patch.object(register, "confirmation", side_effect=fixture_confirmation), \
            contextlib.redirect_stdout(io.StringIO()):
        yield confirm


def concurrent_add(root, marker):
    with fixture_authority():
        register.add(root, "G", marker, b"fixture bulletin\n", None, "fixture", [])


def concurrent_amend(root):
    with fixture_authority():
        try:
            register.amend(root, TARGET, 1, TITLE + "修正案", AMENDMENT, STATEMENT, "fixture", [])
        except SystemExit as exc:
            if "expected v1, current is v2" not in str(exc):
                raise


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="governance-register-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = self.temp.name
        self.base = (DRAFTS / "S-agent-procedure" / "asmade.md").read_bytes()
        self.amendment = AMENDMENT.read_bytes()
        self.folder = Path(self.root) / TARGET
        self.folder.mkdir()
        files = {}
        for name, data in (("asmade.md", self.base), ("v1.md", self.base),
                           ("statement.md", b"original statement\n")):
            register.write_frozen(str(self.folder / name), data)
            files[TARGET + "/" + name] = hashlib.sha256(data).hexdigest()
        register.append(self.root, [], {
            "seq": 1, "id": TARGET, "kind": "S", "title": TITLE,
            "version": 1, "path": TARGET + "/", "latest": TARGET + "/v1.md",
            "files": files, "registered_at": "2026-11-07T00:00:00+00:00",
            "confirmation": fixture_confirmation("seed"), "applies": ["*"],
        })
        self.original_chain = (Path(self.root) / "chain.log").read_bytes()

    def amend(self, **kwargs):
        arguments = dict(target=TARGET, expected_version=1, title=TITLE + "修正案",
                         asmade=AMENDMENT, statement=STATEMENT, note="fixture", applies=[])
        arguments.update(kwargs)
        return register.amend(self.root, **arguments)

    def compile(self, amendment=None, base=None):
        return register.compile_amendment(
            self.base if base is None else base,
            self.amendment if amendment is None else amendment, TARGET, 1, TITLE)

    def test_approved_amendment_transaction(self):
        with fixture_authority() as confirm:
            self.amend()
        confirm.assert_called_once()
        displayed = dict(confirm.call_args[0][0])
        self.assertEqual(displayed["修正案原文"], self.amendment)
        self.assertEqual(displayed["说明书"], STATEMENT.read_bytes())
        compilation = (self.folder / "v2.md").read_bytes()
        self.assertEqual(displayed["汇编 " + TARGET + "/v2.md"], compilation)
        chain, problems = register.verify(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(len(chain), 2)
        event = chain[-1]
        self.assertEqual(event["op"], "amend")
        self.assertNotEqual(event["id"], TARGET)
        self.assertEqual(event["amends"]["articles"], [2, 3, 4, 7, 8])
        self.assertTrue((Path(self.root) / "chain.log").read_bytes().startswith(self.original_chain))
        self.assertEqual((self.folder / "asmade.md").read_bytes(), self.base)
        self.assertEqual((self.folder / "v1.md").read_bytes(), self.base)
        prefix, original = register.articles(self.base)
        new_prefix, compiled = register.articles(compilation)
        self.assertEqual(prefix, new_prefix)
        for number in (1, 5, 6, 9, 10):
            self.assertEqual(original[number], compiled[number])
        projection = register.current_entries(chain)
        self.assertEqual(projection[TARGET]["latest"], TARGET + "/v2.md")
        self.assertEqual(projection[TARGET]["hash"], event["hash"])
        self.assertEqual(projection[TARGET]["version"], 2)
        self.assertEqual(projection[TARGET]["applies"], ["*"])
        self.assertEqual(projection[event["id"]]["applies"], [])
        index = (Path(self.root) / "index.yaml").read_text()
        self.assertEqual(index.count('  - id: "' + TARGET + '"'), 1)
        self.assertIn('statement: "' + TARGET + '/statement.md"', index)
        self.assertIn('statement: "' + event["id"] + '/statement.md"', index)
        self.assertIn('latest: "' + TARGET + '/v2.md"', index)
        self.assertIn('amends: "' + TARGET + '"', index)
        for rel in event["files"]:
            self.assertEqual((Path(self.root) / rel).stat().st_mode & 0o777, 0o444)

    def test_stale_version_is_rejected_without_confirmation(self):
        with fixture_authority() as confirm:
            self.amend()
            confirm.reset_mock()
            with self.assertRaisesRegex(SystemExit, "expected v1, current is v2"):
                self.amend()
            confirm.assert_not_called()
        self.assertEqual(len(register.read_chain(self.root)), 2)

    def test_unknown_target_and_empty_statement(self):
        empty = Path(self.root) / "empty-statement"
        empty.write_bytes(b"\n")
        with fixture_authority() as confirm:
            with self.assertRaisesRegex(SystemExit, "registered statute"):
                self.amend(target="S2026-999")
            with self.assertRaisesRegex(SystemExit, "statement is empty"):
                self.amend(statement=empty)
            confirm.assert_not_called()

    def test_rejected_confirmation_writes_no_transaction(self):
        with fixture_authority() as confirm:
            confirm.side_effect = SystemExit("not confirmed")
            with self.assertRaisesRegex(SystemExit, "not confirmed"):
                self.amend()
        self.assertEqual((Path(self.root) / "chain.log").read_bytes(), self.original_chain)
        self.assertFalse((self.folder / "v2.md").exists())
        self.assertEqual(len(list(Path(self.root).glob("S*/"))), 1)

    def test_existing_compilation_is_not_overwritten(self):
        collision = self.folder / "v2.md"
        collision.write_bytes(b"unregistered collision")
        with fixture_authority() as confirm:
            with self.assertRaisesRegex(SystemExit, "refusing to overwrite"):
                self.amend()
            confirm.assert_not_called()
        self.assertEqual(collision.read_bytes(), b"unregistered collision")

    def test_missing_duplicate_unknown_and_mismatched_articles(self):
        text = self.amendment.decode()
        cases = [
            "# Empty\n\n§1 本修正案未点名的条文继续有效。\n",
            text.replace("§2 将", "§9 将", 1),
            text.replace("第三条", "第二条", 1).replace("「§3 ", "「§2 ", 1),
            text.replace("第二条", "第十一条", 1).replace("「§2 ", "「§11 ", 1),
            text.replace("第二条", "第三条", 1),
            text.replace("（S2026-002 v1）", "（S2026-002 v2）", 1),
            text.replace("（S2026-002 v1）", "（S2026-999 v1）", 1),
            text.replace("§6 本修正案未点名的条文继续有效。", ""),
            text + "import os\n",
            text.replace("「§2 ", "「§2 nested\n§11 ", 1),
        ]
        for case in cases:
            with self.subTest(amendment=case[:80]), self.assertRaises(ValueError):
                self.compile(case.encode())
        with self.assertRaisesRegex(ValueError, "duplicate article"):
            self.compile(base=self.base + b"\n" + "§2 duplicate\n".encode())

    def test_generic_target_and_multiline_article(self):
        base = "# Other\n\n§1 unchanged\n\n§2 old\nparagraph\n\n§3 untouched\n".encode()
        amendment = ("# Change\n\n§1 将《Other》（S2031-017 v3）第二条修改为：\n\n"
                     "「§2 new\n\nparagraph」\n\n§2 本修正案未点名的条文继续有效。\n").encode()
        compiled, changed = register.compile_amendment(base, amendment, "S2031-017", 3, "Other")
        self.assertEqual(changed, [2])
        self.assertEqual(compiled, base.replace(b"old\nparagraph", b"new\n\nparagraph"))

    def test_verify_checks_each_amendment_file(self):
        with fixture_authority():
            self.amend()
        event = register.read_chain(self.root)[-1]
        for rel in event["files"]:
            path = Path(self.root) / rel
            original = path.read_bytes()
            path.chmod(0o644)
            path.write_bytes(original + b"tampered\n")
            with self.subTest(path=rel):
                self.assertTrue(register.verify(self.root)[1])
            path.write_bytes(original)
            path.chmod(0o444)
        self.assertEqual(register.verify(self.root)[1], [])

    def test_verify_replays_compilation_even_with_rehashed_event(self):
        with fixture_authority():
            self.amend()
        chain = register.read_chain(self.root)
        event = chain[-1]
        path = self.folder / "v2.md"
        path.chmod(0o644)
        path.write_bytes(path.read_bytes().replace("§1 本法".encode(), "§1 篡改".encode()))
        event["files"][TARGET + "/v2.md"] = register.sha256_file(path)
        event["hash"] = register.entry_hash(event)
        (Path(self.root) / "chain.log").write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in chain))
        self.assertTrue(any("compilation mismatch" in p for p in register.verify(self.root)[1]))

    def test_add_meta_attach_and_legacy_index(self):
        with fixture_authority():
            register.add(self.root, "C", "fixture constitution", b"fixture\n", None, "fixture", [])
            chain = register.read_chain(self.root)
            identifier = chain[-1]["id"]
            register.attach(self.root, identifier, b"fixture explanation\n", "fixture")
            register.meta(self.root, identifier, ["read"], "fixture")
            register.add(self.root, "G", "fixture bulletin", b"fixture\n", None, "fixture", [])
            self.amend()
        chain, problems = register.verify(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(register.current_entries(chain)[identifier]["applies"], ["read"])
        legacy = dict(chain[0])
        legacy.pop("applies")
        self.assertEqual(register.current_entries([legacy])[TARGET]["applies"], [])
        register.write_index(self.root, [legacy])
        self.assertIn("applies: []", (Path(self.root) / "index.yaml").read_text())

    def test_concurrent_writers_are_serialized(self):
        context = multiprocessing.get_context("fork")
        processes = [context.Process(target=concurrent_add, args=(self.root, str(i))) for i in range(4)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail("registration writer did not finish")
            self.assertEqual(process.exitcode, 0)
        chain, problems = register.verify(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(len(chain), 5)
        self.assertEqual(len({e["id"] for e in chain}), 5)

    def test_competing_amendments_commit_once(self):
        context = multiprocessing.get_context("fork")
        processes = [context.Process(target=concurrent_amend, args=(self.root,)) for _ in range(2)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(15)
            if process.is_alive():
                process.terminate()
                process.join()
                self.fail("amendment writer did not finish")
            self.assertEqual(process.exitcode, 0)
        chain, problems = register.verify(self.root)
        self.assertEqual(problems, [])
        self.assertEqual(len(chain), 2)

    def test_production_authority_rejects_unprivileged_caller(self):
        with mock.patch.object(register.os, "geteuid", return_value=501), \
                mock.patch.dict(os.environ, {"SUDO_USER": "root", "SUDO_UID": "0"}):
            with self.assertRaisesRegex(SystemExit, "run through sudo"):
                self.amend()
        self.assertEqual((Path(self.root) / "chain.log").read_bytes(), self.original_chain)

    def test_production_confirmation_requires_terminal(self):
        with mock.patch.object(register, "require_sudo"), \
                mock.patch.object(register.sys.stdin, "isatty", return_value=False):
            with self.assertRaisesRegex(SystemExit, "interactive terminal"):
                register.confirm((("fixture", b"text"),))


if __name__ == "__main__":
    unittest.main()
