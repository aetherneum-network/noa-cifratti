"""The pack runs alone and offline: no network module, no dependency, sockets refused everywhere."""
import ast
import socket
import sys
import unittest

import tests
from tests import _util as u

NETWORK_MODULES = {"socket", "ssl", "http", "urllib", "ftplib", "smtplib", "imaplib", "poplib", "telnetlib", "xmlrpc",
                   "socketserver", "asyncio", "webbrowser", "requests", "httpx", "aiohttp", "anthropic", "openai"}
LOCAL = {"noascan", "corpus", "tabletop", "threatmodel", "scenarios", "tools", "tests", "score", "manual"}   # score, manual: eval/*.py
SOCKET_BLOCKERS = {"tests/__init__.py", "tests/offline/sitecustomize.py", "tests/test_offline.py"}


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    return names


def all_sources():
    return u.pack_sources() + sorted(p for p in (u.ROOT / "tests").rglob("*.py") if "__pycache__" not in p.parts)


class Imports(unittest.TestCase):
    def test_only_the_standard_library_and_the_pack_itself_are_imported(self):
        for path in all_sources():
            rel = path.relative_to(u.ROOT).as_posix()
            with self.subTest(file=rel):
                foreign = sorted(n for n in imports(path) if n not in sys.stdlib_module_names and n not in LOCAL)
                self.assertEqual(foreign, [])

    def test_no_network_module_is_imported(self):
        for path in all_sources():
            rel = path.relative_to(u.ROOT).as_posix()
            with self.subTest(file=rel):
                used = sorted(imports(path) & NETWORK_MODULES)
                self.assertEqual(used, ["socket"] if rel in SOCKET_BLOCKERS else [])

    def test_no_dependency_file_exists(self):
        for name in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
                     "poetry.lock", "package.json"):
            self.assertFalse((u.ROOT / name).exists(), name)

    def test_processes_are_started_only_where_declared(self):
        users = sorted(p.relative_to(u.ROOT).as_posix() for p in u.pack_sources() if "subprocess" in imports(p))
        self.assertEqual(users, ["eval/score.py", "noascan/gitio.py", "scenarios/S03/check.py", "tools/manifest.py"])
        for rel in users:
            tree = ast.parse((u.ROOT / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    for kw in node.keywords:
                        self.assertFalse(kw.arg == "shell" and getattr(kw.value, "value", None) is True, rel)

    def test_git_is_only_ever_asked_to_read(self):
        read_only = {"rev-parse", "diff", "show-ref", "cat-file", "ls-tree"}
        asked = set()
        for rel in ("eval/score.py", "noascan/gitio.py", "tools/manifest.py"):
            tree = ast.parse((u.ROOT / rel).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") in ("git", "_run"):
                    first = next((a for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)), None)
                    self.assertIsNotNone(first, f"{rel}:{node.lineno}: the git sub-command must be a literal")
                    asked.add(first.value)
        self.assertEqual(asked, read_only)


class Sockets(unittest.TestCase):
    def test_a_socket_cannot_be_created_in_the_test_process(self):
        with self.assertRaises(tests.NetworkBlocked):
            socket.socket()
        with self.assertRaises(tests.NetworkBlocked):
            socket.create_connection(("127.0.0.1", 9), timeout=1)
        with self.assertRaises(tests.NetworkBlocked):
            socket.getaddrinfo("unreachable.example", 443)

    def test_a_child_process_cannot_create_one_either(self):
        proc = u.run(["-c", "import socket; socket.socket()"])
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"NetworkBlocked", proc.stderr)
        proc = u.run(["-c", "import socket; socket.getaddrinfo('unreachable.example', 443)"])
        self.assertIn(b"NetworkBlocked", proc.stderr)

    def test_the_scenarios_pass_with_the_network_refused(self):
        proc = u.run(["scenarios/run_all.py"])
        self.assertEqual(proc.returncode, 0, proc.stdout.decode("utf-8", "replace")[-2000:])
        self.assertIn(b"Scenarios: 10/10 PASS", proc.stdout)

    def test_the_command_line_runs_with_the_network_refused(self):
        self.assertEqual(u.run(["-m", "noascan", "rules-test"]).returncode, 0)
        self.assertEqual(u.run(["tools/selfscan.py", "--check"]).returncode, 0)


if __name__ == "__main__":
    unittest.main()
