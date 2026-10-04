#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that each built firmware image fits the slot it is meant for.

Run from `firmware/`, after `pio run`. `pio run` already refuses an image that does not
fit its partition table, so this is not checking that. It is checking the thing the slot
layout exists to protect, from the outside: that the image is where the flash tool will
look for it, and that it is smaller than the slot the shipped table declares -- computed
from that table rather than from a constant here.

The previous check was `ls -l <path>`, and it failed in a way worth recording. It looked
for `.pio/build/<env>/firmware.bin` and reported "No such file or directory" immediately
below a build that had plainly written exactly that path two lines earlier. A path-based
check either passes or sends you hunting, and it says nothing about the thing you care
about, which is the size.

So this does not assume a location. It looks in the expected place, and if the image is
not there it searches the tree and prints every path it considered. A failure now names
the directory rather than asserting one.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# env -> (table it is built against, the app slot the sniffer occupies)
ENVIRONMENTS = {
    "heltec_v4_sniffer_standalone": ("snifferboot.csv", 0),
    "heltec_v4_sniffer_beacon_standalone": ("snifferboot.csv", 0),
}

# Directories never worth searching for an image.
SKIP = {".git", "__pycache__", "node_modules", "libdeps"}


def candidates(env: str) -> list[Path]:
    """Where an image for `env` could plausibly be, in the order we prefer."""
    out = [ROOT / "firmware" / ".pio" / "build" / env / "firmware.bin"]
    # PlatformIO resolves its build directory relative to the directory it was invoked
    # from, not the project directory, so a `-d firmware` build lands somewhere else
    # entirely. Look there too rather than guessing which convention is in force.
    out.append(ROOT / ".pio" / "build" / env / "firmware.bin")
    return out


def app_slot_bytes(table: Path, index: int) -> tuple[int, int]:
    """Return (offset, size) of `ota_<index>` in a shipped partition table."""
    for line in table.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        cols = [c.strip() for c in text.split(",")]
        if len(cols) < 5 or cols[0] != f"ota_{index}":
            continue
        return int(cols[3], 0), int(cols[4], 0)
    raise SystemExit(f"error: {table.name} has no ota_{index} row")


def main() -> int:
    problems = 0

    for env, (table_name, slot) in sorted(ENVIRONMENTS.items()):
        image = next((path for path in candidates(env) if path.is_file()), None)

        if image is None:
            print(f"missing  no firmware.bin for {env}. Looked in:", file=sys.stderr)
            for path in candidates(env):
                print(f"            {path.relative_to(ROOT)}", file=sys.stderr)
            # Say where it actually is, rather than only where it was not.
            for found in sorted(ROOT.rglob(f"build/{env}/firmware.bin")):
                if not SKIP & set(found.relative_to(ROOT).parts):
                    print(f"          found instead: {found.relative_to(ROOT)}",
                          file=sys.stderr)
            problems += 1
            continue

        offset, capacity = app_slot_bytes(ROOT / "firmware" / "partitions" / table_name, slot)
        size = image.stat().st_size
        fits = size <= capacity

        print(f"{env:<38} {size:>9,} B into ota_{slot} "
              f"(0x{offset:06X}, {capacity:,} B) "
              f"{'fits' if fits else 'DOES NOT FIT'}")
        print(f"{'':<38} at {image.relative_to(ROOT)}")

        if not fits:
            print(
                f"{'':<38} {size - capacity:,} B over. The bootloader refuses an "
                f"oversized image at flash time with nothing useful on the console.",
                file=sys.stderr,
            )
            problems += 1

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
