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
from typing import BinaryIO, Iterable, Iterator, Optional, Sequence, Tuple
from urllib.parse import urlsplit

_PRIVATE_MODULE = ("github.com/conductera/" + "control-plane").encode("ascii")
_PRIVATE_TLDS = {"internal", "corp", "local"}
_PRIVATE_PRODUCTS = {"nexus", "artifactory"}
_URL_RE = re.compile(r"(?i)\b(?:https?|ssh|git)://[^\s<>\"']+")
_HOSTNAME_RE = re.compile(
    r"(?<![\w.\-\u3002\uff0e\uff61])"
    r"(?:[^\W_]|-)+(?:[.\u3002\uff0e\uff61](?:[^\W_]|-)+)+"
    r"(?::[0-9]+)?(?:[/?#][^\s<>\"']*)?",
    re.UNICODE,
)
_BARE_PRODUCT_HOST_RE = re.compile(
    r"(?i)(?<![\w./\-\u3002\uff0e\uff61])(?:nexus|artifactory)"
    r"(?=:[0-9]+(?:[/?#\s]|$)|/)",
    re.UNICODE,
)
_OBJECT_ID_RE = re.compile(br"[0-9a-f]{40}(?:[0-9a-f]{24})?")

# Every file/blob is bounded before it is read into memory. Larger tracked,
# committed, or untracked inputs fail closed rather than being silently skipped.
MAX_SCANNED_BYTES = 16 * 1024 * 1024


class GitScanError(ValueError):
    """Raised when Git cannot provide a complete, trustworthy object scan."""


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


def _index_entries() -> list[Tuple[str, str]]:
    result = subprocess.run(
        ["git", "ls-files", "--stage", "-z"],
        check=True,
        stdout=subprocess.PIPE,
    )
    entries: list[Tuple[str, str]] = []
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        metadata, separator, encoded_path = record.partition(b"\t")
        fields = metadata.split()
        if not separator or len(fields) != 3 or not _OBJECT_ID_RE.fullmatch(fields[1]):
            raise GitScanError("git ls-files returned malformed index metadata")
        path = encoded_path.decode("utf-8", errors="surrogateescape")
        entries.append((fields[1].decode("ascii"), path))
    return entries


def _read_worktree_bytes(path: Path) -> Optional[bytes]:
    if path.is_symlink():
        content = os.readlink(str(path)).encode("utf-8", errors="surrogateescape")
        if len(content) > MAX_SCANNED_BYTES:
            raise ValueError("symbolic link target exceeds scan size limit")
        return content
    if not path.is_file():
        return None
    if path.stat().st_size > MAX_SCANNED_BYTES:
        raise ValueError("file exceeds scan size limit")
    with path.open("rb") as input_file:
        content = input_file.read(MAX_SCANNED_BYTES + 1)
    if len(content) > MAX_SCANNED_BYTES:
        raise ValueError("file exceeds scan size limit")
    return content


def _hostname_from_token(token: str) -> Optional[str]:
    candidate = token.rstrip(".,;)]}\u3002\uff0e\uff61")
    try:
        if "://" in candidate:
            return urlsplit(candidate).hostname
    except ValueError:
        return None

    authority = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if authority.count(":") == 1:
        authority = authority.split(":", 1)[0]
    return authority.rstrip(".\u3002\uff0e\uff61") or None


def _ascii_hostname(hostname: str) -> Optional[str]:
    try:
        return hostname.encode("idna").decode("ascii").casefold().rstrip(".")
    except UnicodeError:
        return None


def _private_host_tokens(line: str) -> list[str]:
    url_matches = list(_URL_RE.finditer(line))
    matches = list(url_matches)
    for expression in (_HOSTNAME_RE, _BARE_PRODUCT_HOST_RE):
        for match in expression.finditer(line):
            if any(
                match.start() >= url_match.start() and match.end() <= url_match.end()
                for url_match in url_matches
            ):
                continue
            matches.append(match)

    private_tokens: list[str] = []
    seen_hostnames: set[str] = set()
    for match in sorted(matches, key=lambda item: (item.start(), item.end())):
        token = match.group(0)
        hostname = _hostname_from_token(token)
        if hostname is None:
            continue
        normalized_hostname = _ascii_hostname(hostname)
        if not normalized_hostname:
            continue
        labels = normalized_hostname.split(".")
        if (
            labels[-1] in _PRIVATE_TLDS
            or any(label in _PRIVATE_PRODUCTS for label in labels)
        ) and normalized_hostname not in seen_hostnames:
            seen_hostnames.add(normalized_hostname)
            private_tokens.append(token)
    return private_tokens


def _safe_path(path: Optional[str]) -> str:
    if path is None:
        return "<unknown>"
    return json.dumps(path, ensure_ascii=True)


def _check_content(content: bytes, source: str) -> list[str]:
    violations: list[str] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        if _PRIVATE_MODULE in line.lower():
            violations.append(f"{source}:{line_number}: private module reference")
        decoded_line = line.decode("utf-8", errors="replace")
        for _token in _private_host_tokens(decoded_line):
            violations.append(f"{source}:{line_number}: private registry host")
    return violations


def _check_module_shape(paths: Iterable[str]) -> list[str]:
    violations: list[str] = []
    for path in paths:
        name = PurePosixPath(path).name
        if name == "go.work":
            violations.append(f"{_safe_path(path)}: workspace file is not allowed")
        elif name == "go.mod" and path != "go.mod":
            violations.append(f"{_safe_path(path)}: nested module is not allowed")
    return violations


def _go_mod_json(go: str) -> dict[str, object]:
    environment = os.environ.copy()
    environment["GOWORK"] = "off"
    result = subprocess.run(
        [go, "mod", "edit", "-json"],
        check=True,
        env=environment,
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


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise GitScanError("git cat-file ended before returning a complete object")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _discard_exact(stream: BinaryIO, size: int) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise GitScanError("git cat-file ended before returning a complete object")
        remaining -= len(chunk)


class _GitBlobReader:
    def __init__(self) -> None:
        self._process = subprocess.Popen(
            ["git", "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

    def __enter__(self) -> "_GitBlobReader":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        if self._process.stdin is not None:
            self._process.stdin.close()
        if self._process.stdout is not None:
            self._process.stdout.close()
        return_code = self._process.wait()
        if return_code != 0 and _type is None:
            raise GitScanError("git cat-file failed while reading blobs")

    def read(self, oid: str) -> Tuple[str, int, Optional[bytes]]:
        if self._process.stdin is None or self._process.stdout is None:
            raise GitScanError("git cat-file streams are unavailable")
        self._process.stdin.write(oid.encode("ascii") + b"\n")
        self._process.stdin.flush()
        header = self._process.stdout.readline()
        fields = header.rstrip(b"\n").split()
        if len(fields) == 2 and fields[1] == b"missing":
            raise GitScanError(f"git object {oid} is missing")
        if len(fields) != 3 or not fields[2].isdigit():
            raise GitScanError("git cat-file returned malformed object metadata")
        object_type = fields[1].decode("ascii", errors="strict")
        size = int(fields[2])
        if size > MAX_SCANNED_BYTES:
            _discard_exact(self._process.stdout, size)
            delimiter = self._process.stdout.read(1)
            if delimiter != b"\n":
                raise GitScanError("git cat-file returned malformed object framing")
            return object_type, size, None
        content = _read_exact(self._process.stdout, size)
        delimiter = self._process.stdout.read(1)
        if delimiter != b"\n":
            raise GitScanError("git cat-file returned malformed object framing")
        return object_type, size, content


def _check_worktree_files(paths: Sequence[str]) -> list[str]:
    violations: list[str] = []
    for relative_path in paths:
        source = f"worktree path={_safe_path(relative_path)}"
        try:
            content = _read_worktree_bytes(Path(relative_path))
        except ValueError as error:
            violations.append(f"{source}: {error}")
            continue
        if content is not None:
            violations.extend(_check_content(content, source))
    return violations


def _check_index(entries: Sequence[Tuple[str, str]]) -> list[str]:
    violations: list[str] = []
    with _GitBlobReader() as reader:
        for oid, path in entries:
            source = f"index path={_safe_path(path)} oid={oid}"
            object_type, size, content = reader.read(oid)
            if object_type != "blob":
                raise GitScanError(f"index object {oid} is not a blob")
            if content is None:
                violations.append(
                    f"{source}: blob size {size} exceeds {MAX_SCANNED_BYTES}-byte scan limit"
                )
            else:
                violations.extend(_check_content(content, source))
    return violations


def _nul_records(stream: BinaryIO) -> Iterator[bytes]:
    pending = b""
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        fields = (pending + chunk).split(b"\0")
        pending = fields.pop()
        for field in fields:
            yield field
    if pending:
        raise GitScanError("git rev-list returned unterminated object metadata")


def _check_history() -> list[str]:
    violations: list[str] = []
    revision_process = subprocess.Popen(
        ["git", "rev-list", "--objects", "--all", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if revision_process.stdout is None:
        revision_process.kill()
        raise GitScanError("git rev-list output is unavailable")

    pending_oid: Optional[str] = None
    try:
        with _GitBlobReader() as reader:
            for record in _nul_records(revision_process.stdout):
                if record.startswith(b"path="):
                    if pending_oid is None:
                        raise GitScanError("git rev-list returned a path without an object")
                    path = record[len(b"path=") :].decode(
                        "utf-8", errors="surrogateescape"
                    )
                    oid = pending_oid
                    pending_oid = None
                else:
                    if pending_oid is not None:
                        object_type, size, content = reader.read(pending_oid)
                        if object_type == "blob":
                            source = f"history blob oid={pending_oid}"
                            if content is None:
                                violations.append(
                                    f"{source}: blob size {size} exceeds "
                                    f"{MAX_SCANNED_BYTES}-byte scan limit"
                                )
                            else:
                                violations.extend(_check_content(content, source))
                    if not _OBJECT_ID_RE.fullmatch(record):
                        raise GitScanError("git rev-list returned malformed object metadata")
                    pending_oid = record.decode("ascii")
                    continue

                object_type, size, content = reader.read(oid)
                if object_type != "blob":
                    continue
                source = f"history path={_safe_path(path)} oid={oid}"
                if content is None:
                    violations.append(
                        f"{source}: blob size {size} exceeds "
                        f"{MAX_SCANNED_BYTES}-byte scan limit"
                    )
                else:
                    violations.extend(_check_content(content, source))

            if pending_oid is not None:
                object_type, size, content = reader.read(pending_oid)
                if object_type == "blob":
                    source = f"history blob oid={pending_oid}"
                    if content is None:
                        violations.append(
                            f"{source}: blob size {size} exceeds "
                            f"{MAX_SCANNED_BYTES}-byte scan limit"
                        )
                    else:
                        violations.extend(_check_content(content, source))
    except Exception:
        revision_process.kill()
        revision_process.wait()
        raise
    finally:
        revision_process.stdout.close()

    if revision_process.wait() != 0:
        raise GitScanError("git rev-list failed during full-history scan")
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--go", default="go", help="Go command to invoke")
    args = parser.parse_args()

    try:
        paths = _repository_files()
        index_entries = _index_entries()
        violations = _check_module_shape(paths)
        violations.extend(_check_replacements(_go_mod_json(args.go)))
        violations.extend(_check_worktree_files(paths))
        violations.extend(_check_index(index_entries))
        violations.extend(_check_history())
    except (
        OSError,
        subprocess.CalledProcessError,
        json.JSONDecodeError,
        UnicodeError,
        ValueError,
    ) as error:
        print(f"public boundary check failed: {error}", file=sys.stderr)
        return 1

    if violations:
        for violation in violations:
            print(f"public boundary violation: {violation}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
