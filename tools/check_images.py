#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that each built firmware image fits the slot it is meant for.

Run from `firmware/`, after `pio run`. `pio run` already refuses an image that does not
fit its partition table, so this is not checking that. It is checking the thing the
layout exists to protect, from the outside:

* the image is where the flash tool will look for it, so a renamed build directory or a
  `-d` flag that moved `.pio` produces a failed flash rather than a surprising one;
* the image is smaller than the slot the shipped table declares, computed from that
  table rather than from a constant in this file.

`ls -l` was the previous check, and it passed or failed on the path alone. It reported
success for a build whose output had landed in a different directory than the flasher
reads from -- which is exactly the situation that produces a board that boots its old
firmware after a successful flash.
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIRMWARE = ROOT / "firmware"

# env -> (table it was built against, the app slot the sniffer occupies)
ENVIRONMENTS = {
    "heltec_v4_sniffer_standalone": ("snifferboot.csv", 0),
    "heltec_v4_sniffer_beacon_standalone": ("snifferboot.csv", 0),
}


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
        image = FIRMWARE / ".pio" / "build" / env / "firmware.bin"
        table = FIRMWARE / "partitions" / table_name

        if not image.is_file():
            print(f"missing  {image.relative_to(ROOT)}")
            problems += 1
            continue

        offset, capacity = app_slot_bytes(table, slot)
        size = image.stat().st_size
        fits = size <= capacity

        print(
            f"{env:<38} {size:>9,} B into ota_{slot} "
            f"(0x{offset:06X}, {capacity:,} B) "
            f"{'fits' if fits else 'DOES NOT FIT'}"
        )
        if not fits:
            print(
                f"          {size - capacity:,} B over. The bootloader will refuse the "
                f"image at flash time with nothing useful on the console.",
                file=sys.stderr,
            )
            problems += 1

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
