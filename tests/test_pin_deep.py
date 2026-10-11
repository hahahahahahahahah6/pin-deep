"""Smoke tests for pin-deep. All offline: a FakeFetcher replays fixture action.yml files."""
from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pin_deep.cli import main as cli_main
from pin_deep.core import Scanner, find_uses_values, parse_uses

SHA_A = "a" * 40
SHA_B = "b" * 40
SHA_C = "c" * 40
SHA_D = "d" * 40

# root@SHA_A pulls in one unpinned action, one pinned action, and noise
ROOT_YML = """\
name: root
runs:
  using: composite
  steps:
    - uses: actions/checkout@v4
    - uses: actions/setup-python@%s
    - uses: ./local-action
    - uses: docker://alpine:3.20
    - run: echo hi
""" % SHA_A

SETUP_PYTHON_YML = """\
name: setup-python
runs:
  using: composite
  steps:
    - uses: actions/cache@v3
    - uses: actions/cache@%s
    - uses: actions/tool-cache@abc1234
""" % SHA_B

CACHE_YML = """\
name: cache
runs:
  using: composite
  steps:
    - uses: actions/github-script@%s
""" % SHA_C

# cycle: cyc-a -> cyc-b -> cyc-a
CYC_A_YML = "runs:\n  using: composite\n  steps:\n    - uses: org/cyc-b@%s\n" % SHA_D
CYC_B_YML = "runs:\n  using: composite\n  steps:\n    - uses: org/cyc-a@%s\n" % SHA_A


class FakeFetcher:
    def __init__(self, files):
        self.files = files  # {(owner, repo, ref, subpath): text}
        self.calls: list[tuple] = []
        self.last_error = ""

    def get_action_yml(self, owner, repo, ref, subpath=""):
        self.calls.append((owner, repo, ref, subpath))
        key = (owner, repo, ref, subpath)
        if key in self.files:
            return self.files[key]
        self.last_error = "HTTP 404 for fake url"
        return None


def make_scanner(files, max_depth=3):
    return Scanner(fetcher=FakeFetcher(files), max_depth=max_depth)


FILES = {
    ("acme", "root", SHA_A, ""): ROOT_YML,
    ("actions", "setup-python", SHA_A, ""): SETUP_PYTHON_YML,
    ("actions", "cache", SHA_B, ""): CACHE_YML,
    ("org", "cyc-a", SHA_A, ""): CYC_A_YML,
    ("org", "cyc-b", SHA_D, ""): CYC_B_YML,
}


class TestParsing(unittest.TestCase):
    def test_find_uses_values_in_workflow(self):
        text = """\
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - name: quoted
        uses: "actions/setup-python@%s"
      - uses: 'docker://alpine:3.20'
""" % SHA_A
        self.assertEqual(find_uses_values(text),
                         ["actions/checkout@v4",
                          f"actions/setup-python@{SHA_A}",
                          "docker://alpine:3.20"])

    def test_find_uses_ignores_other_keys(self):
        text = "name: uses are cool\nrun: echo uses: not-a-key\n"
        self.assertEqual(find_uses_values(text), [])

    def test_pin_status_matrix(self):
        cases = [
            (f"actions/checkout@{SHA_A}", "pinned"),
            (f"actions/checkout@{'e' * 64}", "pinned"),
            ("actions/checkout@v4", "unpinned"),
            ("actions/checkout@main", "unpinned"),
            ("actions/checkout", "unpinned"),
            ("actions/checkout@abc1234", "short-sha"),
            ("actions/checkout@feature/foo", "unpinned"),
            ("owner/repo/sub/dir@%s" % SHA_A, "pinned"),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                ref = parse_uses(value)
                self.assertEqual(ref.status, expected)
                self.assertEqual(ref.kind, "action")

    def test_local_docker_dynamic_skipped(self):
        for value, kind in [("./local", "local"), ("../up", "local"),
                            ("docker://alpine:3.20", "docker"),
                            ("actions/x@${{ github.sha }}", "dynamic")]:
            with self.subTest(value=value):
                ref = parse_uses(value)
                self.assertNotEqual(ref.kind, "action")
        scanner = make_scanner({})
        scanner.scan_text("- uses: ./local\n- uses: docker://alpine:3.20\n")
        self.assertEqual(scanner.findings, [])


class TestRecursion(unittest.TestCase):
    def test_recursive_nested_unpinned_flagged(self):
        scanner = make_scanner(FILES)
        scanner.scan_ref(f"acme/root@{SHA_A}")
        by_uses = {f.uses: f for f in scanner.findings}
        # depth-1: unpinned tag inside the pinned root
        self.assertIn("actions/checkout@v4", by_uses)
        self.assertEqual(by_uses["actions/checkout@v4"].depth, 1)
        self.assertEqual(by_uses["actions/checkout@v4"].chain,
                         [f"acme/root@{SHA_A}", "actions/checkout@v4"])
        # depth-2: unpinned tag inside the pinned setup-python
        self.assertIn("actions/cache@v3", by_uses)
        self.assertEqual(by_uses["actions/cache@v3"].depth, 2)
        # short sha is a warning, not an unpinned finding
        self.assertIn("actions/tool-cache@abc1234", by_uses)
        self.assertEqual(by_uses["actions/tool-cache@abc1234"].status, "short-sha")

    def test_unpinned_root_is_flagged_not_recursed(self):
        scanner = make_scanner(FILES)
        scanner.scan_ref("acme/root@v1")
        self.assertEqual(len(scanner.findings), 1)
        self.assertEqual(scanner.findings[0].status, "unpinned")
        self.assertEqual(scanner.fetcher.calls, [])

    def test_max_depth_stops_recursion(self):
        scanner = make_scanner(FILES, max_depth=1)
        scanner.scan_ref(f"acme/root@{SHA_A}")
        fetched = {(c[0], c[1]) for c in scanner.fetcher.calls}
        # root's action.yml fetched, but pinned children are reported, not followed
        self.assertIn(("acme", "root"), fetched)
        self.assertNotIn(("actions", "setup-python"), fetched)
        self.assertNotIn(("actions", "cache"), fetched)
        by_uses = {f.uses: f for f in scanner.findings}
        self.assertIn("actions/checkout@v4", by_uses)   # depth 1, still reported
        self.assertNotIn("actions/cache@v3", by_uses)   # depth 2, never reached

    def test_cycle_terminates(self):
        scanner = make_scanner(FILES, max_depth=10)
        scanner.scan_ref(f"org/cyc-a@{SHA_A}")
        self.assertLessEqual(len(scanner.fetcher.calls), 2)
        self.assertEqual(scanner.findings, [])

    def test_missing_action_yml_is_error_finding(self):
        scanner = make_scanner({})
        scanner.scan_ref(f"acme/root@{SHA_A}")
        self.assertEqual(len(scanner.findings), 1)
        self.assertEqual(scanner.findings[0].status, "error")
        self.assertIn("404", scanner.findings[0].note)


class TestCli(unittest.TestCase):
    def run_cli(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(argv)
        return code, buf.getvalue()

    def test_cli_exit_1_on_unpinned(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("steps:\n  - uses: actions/checkout@v4\n")
            path = fh.name
        try:
            code, out = self.run_cli([path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 1)
        self.assertIn("actions/checkout@v4", out)

    def test_cli_exit_0_when_clean(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as fh:
            fh.write("steps:\n  - uses: ./local\n  - uses: docker://alpine:3.20\n")
            path = fh.name
        try:
            code, out = self.run_cli([path])
        finally:
            os.unlink(path)
        self.assertEqual(code, 0)
        self.assertIn("All clear", out)

    def test_cli_json_format(self):
        code, out = self.run_cli(["--format", "json", "actions/checkout@v4"])
        self.assertEqual(code, 1)
        data = json.loads(out)
        self.assertEqual(data[0]["uses"], "actions/checkout@v4")
        self.assertEqual(data[0]["status"], "unpinned")
        self.assertIn("chain", data[0])


if __name__ == "__main__":
    unittest.main()
