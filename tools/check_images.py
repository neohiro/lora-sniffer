#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check that a built firmware image fits the slot it is meant for.

Run from `firmware/`, after `pio run`. `pio run` already refuses an image that does not
fit its partition table, so this is not checking that. It is checking the thing the slot
layout exists to protect, from the outside: that the image is where the flash tool will
look for it, and that it is smaller than the slot the shipped table declares -- computed
from that table rather than from a constant here.

    python ../tools/check_images.py                       # every environment
    python ../tools/check_images.py heltec_v4_sniffer_standalone   # just one

**Check one environment at a time.** PlatformIO deletes the previous environment's build
directory when it builds the next one: `pio run -e A` then `pio run -e B` leaves
`.pio/build/B` and no `.pio/build/A`. That is not a documented guarantee so much as an
observed behaviour, but it is what the tool does, and it is why CI checks each image
directly after building it rather than after building all of them. Checking both at the
end reported one environment's image missing, immediately below a build log that said it
had been written.

The previous check was `ls -l <path>`, which reported "No such file or directory"
immediately below a build that had plainly written exactly that path. A path-based check
either passes or sends you hunting, and it says nothing about the property you care about,
which is the size.
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


def check(env: str) -> bool:
    """Check one environment. Returns True when it passed."""
    table_name, slot = ENVIRONMENTS[env]
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
        return False

    offset, capacity = app_slot_bytes(ROOT / "firmware" / "partitions" / table_name, slot)
    size = image.stat().st_size
    fits = size <= capacity

    print(f"{env:<38} {size:>9,} B into ota_{slot} "
          f"(0x{offset:06X}, {capacity:,} B) "
          f"{'fits' if fits else 'DOES NOT FIT'}")
    print(f"{'':<38} at {image.relative_to(ROOT)}")

    if not fits:
        print(
            f"{'':<38} {size - capacity:,} B over. The bootloader refuses an oversized "
            f"image at flash time with nothing useful on the console.",
            file=sys.stderr,
        )
    return fits


def main() -> int:
    requested = sys.argv[1:]
    unknown = [name for name in requested if name not in ENVIRONMENTS]
    if unknown:
        print(
            f"error: unknown environment(s): {', '.join(unknown)}. "
            f"Known: {', '.join(sorted(ENVIRONMENTS))}",
            file=sys.stderr,
        )
        return 2

    problems = sum(0 if check(env) else 1 for env in (requested or sorted(ENVIRONMENTS)))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
