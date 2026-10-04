#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create the repository's labels.

Kept as a script rather than a pile of `gh label create` calls so the set is
reviewable in a diff and reproducible: `python tools/make_labels.py`.

The default GitHub labels are kept and made specific, because the point of a label set
is that `bug` means something here. This project has two failure modes worth telling
apart: something decided a frame means the wrong thing, and something decided nothing at
all about a frame it should have named.

Every description is at most 100 characters. GitHub's limit is not obvious from the API
error -- a longer one comes back as a bare 422 "Invalid request", which reads exactly
like "this label already exists" if you are not looking closely. `assert_label_lengths()`
below checks it before the first request, so a re-run cannot quietly skip half the set.
"""
from __future__ import annotations

import json
import subprocess
import sys

REPO = "neohiro/lora-sniffer"

# GitHub rejects a label description longer than this, with an error that does not say so.
MAX_DESCRIPTION = 100

# name, colour, description
LABELS: list[tuple[str, str, str]] = [
    # --- correctness ------------------------------------------------------
    (
        "attribution",
        "d5314e",
        "A frame was attributed to the wrong protocol or node, or without the evidence.",
    ),
    (
        "decoder",
        "d5314e",
        "A protocol decoder misreads a frame: wrong offsets, lengths or field order, or a "
        "trusted length.",
    ),
    (
        "capture-path",
        "d5314e",
        "The receive path dropped, truncated, reordered or duplicated a record.",
    ),
    (
        "untraceable",
        "fbca04",
        "A frame arrived that nothing could name. Bring the raw bytes.",
    ),
    # --- hardware bring-up ------------------------------------------------
    (
        "bring-up",
        "1d76db",
        "Needs a board on a bench: hardware verification, pin maps, modem behaviour.",
    ),
    (
        "sync-word",
        "1d76db",
        "Does packet mode deliver the SX1262 preamble byte? Still an open question.",
    ),
    (
        "radio-driver",
        "1d76db",
        "Sx1262Promiscuous: RadioLib calls, IRQ handling, receive bookkeeping.",
    ),
    # --- safety -----------------------------------------------------------
    (
        "transmit-gate",
        "b60205",
        "Touches the RX-only guarantee: mayTransmit(), the TX build flag, the CI check.",
    ),
    (
        "memory",
        "b60205",
        "Working set, table capacities, or the boot-time fit check.",
    ),
    # --- host tooling -----------------------------------------------------
    (
        "host-tool",
        "c5def5",
        "tools/sniffctl.py, tools/flash.py, tools/gen_layouts.py, tools/gate.py.",
    ),
    (
        "capture-format",
        "c5def5",
        "The JSONL or wire format, or anything that reads it. Changing it breaks existing "
        "captures.",
    ),
    (
        "slots",
        "c5def5",
        "Partition geometry, slot layouts, or the filesystem pairing rule.",
    ),
    # --- process ----------------------------------------------------------
    (
        "documentation",
        "0075ca",
        "README or docs/, including claims that are not true -- worse than missing docs.",
    ),
    (
        "gate",
        "0075ca",
        "tools/gate.py, the C++ suites, or the CI jobs. The gate is the definition of "
        "passing.",
    ),
    (
        "good first issue",
        "7057ff",
        "Small, self-contained, and verifiable on a laptop with no hardware.",
    ),
    (
        "needs-hardware",
        "e99695",
        "Cannot be verified without a board and an antenna. Not a dismissal.",
    ),
    (
        "question",
        "d876e3",
        "A question about the design, the protocol, or the intent behind a decision.",
    ),
]


def assert_label_lengths() -> list[str]:
    """Report descriptions GitHub would reject, before making a single request."""
    return [
        f"{name}: description is {len(description)} characters, limit is {MAX_DESCRIPTION}"
        for name, _colour, description in LABELS
        if len(description) > MAX_DESCRIPTION
    ]


def request(method: str, path: str, payload: dict | None) -> tuple[int, str, str]:
    args = ["gh", "api", "-X", method, f"repos/{REPO}{path}"]
    if payload is not None:
        args += ["--input", "-"]
    proc = subprocess.run(
        args,
        input=None if payload is None else json.dumps(payload),
        capture_output=True,
        text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def main() -> int:
    too_long = assert_label_lengths()
    if too_long:
        for line in too_long:
            print(f"too long  {line}", file=sys.stderr)
        print(
            "\nThese would be rejected by the API with a bare 422 that reads like "
            "'already exists'. Shorten them.",
            file=sys.stderr,
        )
        return 1

    failures = 0
    for name, colour, description in LABELS:
        body = {"name": name, "color": colour, "description": description}

        # Ask before posting.
        #
        # GitHub answers a duplicate label with "Validation Failed (HTTP 422)" and no
        # mention of the actual problem -- indistinguishable, in the output, from a
        # description that is too long. Guessing from the status code is how this script
        # first reported twelve missing labels as "exists". So: look, then create or
        # update. That also makes a re-run repair the colours of labels whose defaults
        # are wrong for this project, which is most of them.
        code, _out, _err = request("GET", f"/labels/{name}", None)
        if code == 0:
            code, _out, err = request("PATCH", f"/labels/{name}", body)
            action = "updated"
        elif code == 404:
            code, _out, err = request("POST", "/labels", body)
            action = "created"
        else:
            print(f"FAILED   {name}: could not read the label", file=sys.stderr)
            failures += 1
            continue

        if code == 0:
            print(f"{action}  {name}")
        else:
            print(f"FAILED   {name}: {err.strip() or 'unknown error'}", file=sys.stderr)
            failures += 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
