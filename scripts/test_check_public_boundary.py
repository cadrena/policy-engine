#!/usr/bin/env python3
"""Regression tests for the public-boundary checker."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, Iterator, Optional


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CHECKER_PATH = REPOSITORY_ROOT / "scripts" / "check_public_boundary.py"

spec = importlib.util.spec_from_file_location("check_public_boundary", CHECKER_PATH)
if spec is None or spec.loader is None:
    raise RuntimeError("could not load public-boundary checker")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def _private_module() -> str:
    return "github.com/conductera/" + "control-plane"


def _private_url(host: str, suffix: str = "/") -> str:
    return "https://" + host + suffix


def _run(
    args: list[str],
    cwd: Path,
    *,
    check: bool = True,
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        cwd=str(cwd),
        check=check,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _run(["git", *args], repo)


@contextmanager
def _repository() -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as temporary_directory:
        repo = Path(temporary_directory)
        _git(repo, "init", "-q")
        _git(repo, "config", "user.name", "Boundary Tests")
        _git(repo, "config", "user.email", "boundary@example.com")
        (repo / "go.mod").write_text(
            "module example.com/public\n\ngo 1.24.0\n", encoding="utf-8"
        )
        _git(repo, "add", "go.mod")
        _git(repo, "commit", "-q", "-m", "initial")
        yield repo


def _run_checker(
    repo: Path,
    *,
    go: str = "go",
    env: Optional[Dict[str, str]] = None,
) -> subprocess.CompletedProcess[str]:
    checker_env = os.environ.copy()
    checker_env["GOWORK"] = "off"
    if env is not None:
        checker_env.update(env)
    return _run(
        [sys.executable, str(CHECKER_PATH), "--go", go],
        repo,
        check=False,
        env=checker_env,
    )


class PublicBoundaryIntegrationTests(unittest.TestCase):
    def assert_violation(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn("public boundary violation", result.stderr)

    def test_history_only_private_module_is_rejected_without_printing_content(self) -> None:
        with _repository() as repo:
            path = repo / "history-private.txt"
            secret_marker = "do-not-print-this-value"
            path.write_text(
                _private_module() + " " + secret_marker + "\n", encoding="utf-8"
            )
            _git(repo, "add", path.name)
            _git(repo, "commit", "-q", "-m", "add private reference")
            blob_oid = _git(repo, "rev-parse", "HEAD:" + path.name).stdout.strip()
            path.unlink()
            _git(repo, "add", "-u")
            _git(repo, "commit", "-q", "-m", "remove private reference")

            result = _run_checker(repo)

            self.assert_violation(result)
            self.assertIn(path.name, result.stderr)
            self.assertIn(blob_oid, result.stderr)
            self.assertNotIn(secret_marker, result.stderr)

    def test_history_only_private_host_is_rejected(self) -> None:
        with _repository() as repo:
            path = repo / "old-config.txt"
            path.write_text(
                _private_url("registry." + "internal") + "\n", encoding="utf-8"
            )
            _git(repo, "add", path.name)
            _git(repo, "commit", "-q", "-m", "add private host")
            path.unlink()
            _git(repo, "add", "-u")
            _git(repo, "commit", "-q", "-m", "remove private host")

            self.assert_violation(_run_checker(repo))

    def test_nul_containing_worktree_file_is_scanned(self) -> None:
        with _repository() as repo:
            path = repo / "fixture.bin"
            path.write_bytes(b"prefix\0" + _private_module().encode("ascii") + b"\n")

            result = _run_checker(repo)

            self.assert_violation(result)
            self.assertIn(path.name, result.stderr)

    def test_nul_containing_history_blob_is_scanned(self) -> None:
        with _repository() as repo:
            path = repo / "old-fixture.bin"
            path.write_bytes(
                b"prefix\0" + _private_url("nexus").encode("ascii") + b"\n"
            )
            _git(repo, "add", path.name)
            _git(repo, "commit", "-q", "-m", "add binary private host")
            path.unlink()
            _git(repo, "add", "-u")
            _git(repo, "commit", "-q", "-m", "remove binary private host")

            self.assert_violation(_run_checker(repo))

    def test_idna_dot_equivalents_are_normalized_before_host_classification(self) -> None:
        for separator in ("\u3002", "\uff0e", "\uff61"):
            with self.subTest(separator=hex(ord(separator))), _repository() as repo:
                (repo / "config.txt").write_text(
                    _private_url("registry" + separator + "internal") + "\n",
                    encoding="utf-8",
                )

                self.assert_violation(_run_checker(repo))

    def test_benign_public_url_paths_do_not_look_like_private_hosts(self) -> None:
        with _repository() as repo:
            (repo / "links.txt").write_text(
                "\n".join(
                    [
                        _private_url("example.com", "arti" + "factory/path"),
                        _private_url("example.com", "nex" + "us/repository"),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            result = _run_checker(repo)

            self.assertEqual(result.returncode, 0, result.stderr)

    def test_normal_private_hosts_are_rejected(self) -> None:
        hosts = [
            "nexus" + ":5000",
            _private_url("nexus"),
            _private_url("service." + "internal"),
            _private_url("service." + "corp"),
            _private_url("service." + "local"),
        ]
        for index, host in enumerate(hosts):
            with self.subTest(host=host), _repository() as repo:
                (repo / ("host-%d.txt" % index)).write_text(host + "\n", encoding="utf-8")
                self.assert_violation(_run_checker(repo))

    def test_private_module_matching_is_case_insensitive(self) -> None:
        with _repository() as repo:
            (repo / "module.txt").write_text(
                _private_module().upper() + "\n", encoding="utf-8"
            )

            self.assert_violation(_run_checker(repo))

    def test_index_blob_is_scanned_even_when_worktree_copy_is_benign(self) -> None:
        with _repository() as repo:
            path = repo / "staged.txt"
            path.write_text(_private_module() + "\n", encoding="utf-8")
            _git(repo, "add", path.name)
            path.write_text("benign worktree copy\n", encoding="utf-8")

            result = _run_checker(repo)

            self.assert_violation(result)
            self.assertIn("index", result.stderr)

    def test_go_work_and_nested_go_mod_are_rejected(self) -> None:
        for relative_path in ("go.work", "nested/go.mod"):
            with self.subTest(path=relative_path), _repository() as repo:
                path = repo / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("go 1.24.0\n", encoding="utf-8")
                self.assert_violation(_run_checker(repo))

    def test_oversized_worktree_file_fails_closed(self) -> None:
        with _repository() as repo:
            path = repo / "too-large.bin"
            with path.open("wb") as output:
                output.truncate(checker.MAX_SCANNED_BYTES + 1)

            result = _run_checker(repo)

            self.assert_violation(result)
            self.assertIn("exceeds", result.stderr)
            self.assertIn(path.name, result.stderr)

    def test_missing_reachable_git_object_fails_closed(self) -> None:
        with _repository() as repo:
            path = repo / "lost.txt"
            path.write_text("historical content\n", encoding="utf-8")
            _git(repo, "add", path.name)
            _git(repo, "commit", "-q", "-m", "object to corrupt")
            blob_oid = _git(repo, "rev-parse", "HEAD:" + path.name).stdout.strip()
            object_path = repo / ".git" / "objects" / blob_oid[:2] / blob_oid[2:]
            object_path.unlink()

            result = _run_checker(repo)

            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("public boundary check failed", result.stderr)


class PublicBoundaryUnitTests(unittest.TestCase):
    def test_quoted_and_absolute_local_replacements_are_rejected(self) -> None:
        first_old = "example.com/sensitive-old"
        first_new = "../registry." + "internal/secret-marker"
        second_old = "example.com/another-sensitive-old"
        second_new = "/tmp/another-secret-marker"
        module = {
            "Replace": [
                {"Old": {"Path": first_old}, "New": {"Path": first_new}},
                {"Old": {"Path": second_old}, "New": {"Path": second_new}},
            ]
        }

        violations = checker._check_replacements(module)

        self.assertEqual(
            violations,
            [
                "go.mod: local replacement #1 is not allowed",
                "go.mod: local replacement #2 is not allowed",
            ],
        )
        rendered = "\n".join(violations)
        for sensitive_value in (first_old, first_new, second_old, second_new):
            self.assertNotIn(sensitive_value, rendered)

    def test_versioned_module_replacement_is_allowed(self) -> None:
        module = {
            "Replace": [
                {
                    "Old": {"Path": "example.com/a"},
                    "New": {"Path": "example.com/b", "Version": "v1.2.3"},
                }
            ]
        }

        self.assertEqual(checker._check_replacements(module), [])

    def test_malformed_replacement_json_fails_closed(self) -> None:
        with self.assertRaises(ValueError):
            checker._check_replacements({"Replace": "not-a-list"})

    def test_go_mod_edit_forces_workspace_off(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            observed = directory / "observed.txt"
            fake_go = directory / "fake-go"
            fake_go.write_text(
                "#!/bin/sh\n"
                "printf '%s' \"$GOWORK\" > \"$BOUNDARY_OBSERVED\"\n"
                "printf '{\"Replace\": []}\\n'\n",
                encoding="utf-8",
            )
            fake_go.chmod(fake_go.stat().st_mode | stat.S_IXUSR)
            old_observed = os.environ.get("BOUNDARY_OBSERVED")
            old_gowork = os.environ.get("GOWORK")
            os.environ["BOUNDARY_OBSERVED"] = str(observed)
            os.environ["GOWORK"] = str(directory / "outside.go.work")
            try:
                parsed = checker._go_mod_json(str(fake_go))
            finally:
                if old_observed is None:
                    os.environ.pop("BOUNDARY_OBSERVED", None)
                else:
                    os.environ["BOUNDARY_OBSERVED"] = old_observed
                if old_gowork is None:
                    os.environ.pop("GOWORK", None)
                else:
                    os.environ["GOWORK"] = old_gowork

            self.assertEqual(parsed, {"Replace": []})
            self.assertEqual(observed.read_text(encoding="utf-8"), "off")

    def test_malformed_go_mod_json_returns_failure(self) -> None:
        with _repository() as repo:
            fake_go = repo / "fake-go"
            fake_go.write_text("#!/bin/sh\nprintf 'not-json\\n'\n", encoding="utf-8")
            fake_go.chmod(fake_go.stat().st_mode | stat.S_IXUSR)

            result = _run_checker(repo, go=str(fake_go))

            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertIn("public boundary check failed", result.stderr)


class BuildIntegrationTests(unittest.TestCase):
    def test_makefile_wires_boundary_tests_and_forces_workspace_off(self) -> None:
        makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertRegex(makefile, r"(?m)^all:.*\bboundary-test\b")
        self.assertRegex(makefile, r"(?m)^boundary-test:\s*$")
        self.assertIn("GOWORK=off $(GO) list -deps", makefile)

    def test_ci_has_reasonable_job_timeout_and_runs_boundary_tests(self) -> None:
        workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )

        self.assertRegex(workflow, r"(?m)^    timeout-minutes: (?:2[0-9]|30)$")
        self.assertIn("run: make boundary-test", workflow)

    def test_fmt_check_selects_gofmt_from_configured_go_toolchain(self) -> None:
        makefile = (REPOSITORY_ROOT / "Makefile").read_text(encoding="utf-8")

        self.assertIn("$(GO) env GOROOT", makefile)
        self.assertIn("/bin/gofmt", makefile)


if __name__ == "__main__":
    unittest.main()
