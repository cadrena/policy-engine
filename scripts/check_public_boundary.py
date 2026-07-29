#!/usr/bin/env python3
"""Enforce the repository's public Go module boundary."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

_PRIVATE_MODULE = "github.com/conductera/" + "control-plane"
_PRIVATE_TLDS = {"internal", "corp", "local"}
_PRIVATE_PRODUCTS = {"nexus", "artifactory"}
_URL_RE = re.compile(r"(?i)\b(?:https?|ssh|git)://[^\s<>\"']+")
_HOSTNAME_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])"
    r"(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
    r"(?::[0-9]+)?(?:[/?#][^\s<>\"']*)?"
)
_BARE_PRODUCT_HOST_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9_.-])(?:nexus|artifactory)"
    r"(?=:[0-9]+(?:[/?#\s]|$)|/)"
)


def _repository_files() -> list[str]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(
        path.decode("utf-8", errors="surrogateescape")
        for path in result.stdout.split(b"\0")
        if path
    )


def _read_text(path: Path) -> str | None:
    if path.is_symlink():
        return os.readlink(path)
    if not path.is_file():
        return None

    content = path.read_bytes()
    if b"\0" in content:
        return None
    return content.decode("utf-8", errors="replace")


def _hostname_from_token(token: str) -> str | None:
    candidate = token.rstrip(".,;)]}")
    if "://" in candidate:
        return urlsplit(candidate).hostname

    authority = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if authority.count(":") == 1:
        authority = authority.split(":", 1)[0]
    return authority.rstrip(".") or None


def _private_host_tokens(line: str) -> list[str]:
    tokens = [match.group(0) for match in _URL_RE.finditer(line)]
    tokens.extend(match.group(0) for match in _HOSTNAME_RE.finditer(line))
    tokens.extend(match.group(0) for match in _BARE_PRODUCT_HOST_RE.finditer(line))

    private_tokens: list[str] = []
    seen_hostnames: set[str] = set()
    for token in tokens:
        hostname = _hostname_from_token(token)
        if hostname is None:
            continue
        normalized_hostname = hostname.casefold().rstrip(".")
        labels = normalized_hostname.split(".")
        if (
            labels[-1] in _PRIVATE_TLDS
            or any(label in _PRIVATE_PRODUCTS for label in labels)
        ) and normalized_hostname not in seen_hostnames:
            seen_hostnames.add(normalized_hostname)
            private_tokens.append(token)
    return private_tokens


def _check_module_shape(paths: list[str]) -> list[str]:
    violations: list[str] = []
    for path in paths:
        name = PurePosixPath(path).name
        if name == "go.work":
            violations.append(f"{path}: workspace file is not allowed")
        elif name == "go.mod" and path != "go.mod":
            violations.append(f"{path}: nested module is not allowed")
    return violations


def _go_mod_json(go: str) -> dict[str, object]:
    result = subprocess.run(
        [go, "mod", "edit", "-json"],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise ValueError("go mod edit -json returned a non-object value")
    return parsed


def _check_replacements(module: dict[str, object]) -> list[str]:
    violations: list[str] = []
    replacements = module.get("Replace") or []
    if not isinstance(replacements, list):
        raise ValueError("go mod edit -json returned an invalid Replace value")

    for replacement in replacements:
        if not isinstance(replacement, dict):
            raise ValueError("go mod edit -json returned an invalid replacement")
        old = replacement.get("Old") or {}
        new = replacement.get("New") or {}
        if not isinstance(old, dict) or not isinstance(new, dict):
            raise ValueError("go mod edit -json returned an invalid replacement module")
        if not new.get("Version"):
            old_path = old.get("Path", "<unknown>")
            new_path = new.get("Path", "<unknown>")
            violations.append(
                f"go.mod: local replacement is not allowed: {old_path} => {new_path}"
            )
    return violations


def _check_text_files(paths: list[str]) -> list[str]:
    violations: list[str] = []
    for relative_path in paths:
        text = _read_text(Path(relative_path))
        if text is None:
            continue
        for line_number, line in enumerate(text.splitlines(), start=1):
            if _PRIVATE_MODULE in line.casefold():
                violations.append(
                    f"{relative_path}:{line_number}: private module reference"
                )
            for token in _private_host_tokens(line):
                violations.append(
                    f"{relative_path}:{line_number}: private registry host: {token}"
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go", help="Go command to invoke")
    args = parser.parse_args()

    try:
        paths = _repository_files()
        violations = _check_module_shape(paths)
        violations.extend(_check_replacements(_go_mod_json(args.go)))
        violations.extend(_check_text_files(paths))
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, ValueError) as error:
        print(f"public boundary check failed: {error}", file=sys.stderr)
        return 1

    if violations:
        for violation in violations:
            print(f"public boundary violation: {violation}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
