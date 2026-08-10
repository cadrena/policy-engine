#!/bin/sh
# Verify the vendored driver sources have not drifted outside their reviewed fork.
set -eu

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

if command -v sha256sum >/dev/null 2>&1; then
	sha256sum -c internal/sqlitenofollow/FORK_MANIFEST.sha256
else
	shasum -a 256 -c internal/sqlitenofollow/FORK_MANIFEST.sha256
fi
