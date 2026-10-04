#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Report the repository's configuration as GitHub currently sees it.

Run after `tools/make_labels.py` to confirm what actually landed. Exists because the
`gh` CLI's own output is quoted through a shell, and a verification step that depends on
shell quoting is a verification step that silently checks the wrong thing.
"""
from __future__ import annotations

import json
import subprocess
import sys

REPO = "neohiro/lora-sniffer"


def api(path: str) -> object:
    proc = subprocess.run(
        ["gh", "api", f"repos/{REPO}{path}"], capture_output=True, text=True
    )
    if proc.returncode != 0:
        print(f"error reading {path}: {proc.stderr.strip()}", file=sys.stderr)
        return None
    return json.loads(proc.stdout)


def main() -> int:
    problems = 0

    repo = api("")
    if isinstance(repo, dict):
        print(f"visibility      {repo.get('visibility')}")
        print(f"default branch  {repo.get('default_branch')}")
        print(f"discussions     {repo.get('has_discussions')}")
        print(f"issues          {repo.get('has_issues')}")
        desc = repo.get("description") or ""
        print(f"description     {len(desc)} chars")
        if not desc:
            print("  no description", file=sys.stderr)
            problems += 1
        if not repo.get("has_discussions"):
            print("  discussions are off", file=sys.stderr)
            problems += 1
        if repo.get("has_issues") is False:
            print("  issues are off", file=sys.stderr)
            problems += 1

    topics = api("/topics")
    if isinstance(topics, dict):
        names = topics.get("names", [])
        print(f"topics          {', '.join(names)}")
        if not names:
            print("  no topics", file=sys.stderr)
            problems += 1

    labels = api("/labels?per_page=100")
    if isinstance(labels, list):
        print(f"\nlabels ({len(labels)}):")
        for label in sorted(labels, key=lambda entry: entry["name"]):
            text = label.get("description") or ""
            flag = "" if text else "   <-- no description"
            print(f"  {label['name']:<18} {text}{flag}")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
