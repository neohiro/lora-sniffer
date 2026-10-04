#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Flash a Heltec V4 with a sniffer image, or with any of the slot's frameworks.

Exists so the first thing a new user does is not a hand-typed esptool command with
six hex offsets, where one wrong digit writes a partition table over a firmware and
the board stops booting.

    python tools/flash.py --table triboot \
        --bootloader .pio/build/heltec_v4_sniffer/bootloader.bin \
        --part-table-bin .pio/build/heltec_v4_sniffer/partitions.bin \
        --otadata .pio/build/heltec_v4_sniffer/otadata.bin \
        --app sniffer=.pio/build/heltec_v4_sniffer/firmware.bin

Three refusals, each of which has cost somebody a board:

  * A partition table that does not validate against the flash **the chip reports**,
    not against a number in this file. An 8 MB V3 flashed with a five-slot table
    overruns, and the bootloader will not say so.
  * An app image larger than its slot, so the firmware is silently truncated.
  * Two frameworks sharing a filesystem label. Meshtastic mounts LittleFS and
    MeshCore mounts SPIFFS; handing either side the other's type makes it format the
    wrong one on boot and lose the other side's settings with no error anywhere.

The geometry rules are duplicated in C++ (SlotPlan.cpp) and here in Python on
purpose: the flasher has to be able to refuse a bad table on a machine with no C++
compiler, which is exactly the machine a new user is on. tests/test_flash_tool.py
cross-checks the two implementations against the same fixtures, because two copies of
a rule that drift apart is worse than one copy.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PARTITION_DIR = ROOT / "firmware" / "partitions"

# The tables this repository ships. `triboot` is the shared layout the
# meshcore-meshtastic-heltec-v4 project also uses, with the sniffer as slot 2;
# `snifferboot` is the sniffer alone, for a board with nothing else on it.
TABLES = ["triboot", "snifferboot"]

# The two regions that are flashed but never described by a row.
#
# The bootloader goes at 0x0 by ESP-IDF convention, and the partition table occupies the
# 4 KB sector at 0x8000 that the chip's bootloader reserves whether or not the table says
# so. Keeping these as constants is what lets the shipped tables omit both rows, which
# they must: a row at 0x8000 overlaps the table's own extent and the generator rejects
# the file.
BOOTLOADER_OFFSET = 0x0000
PARTITION_TABLE_OFFSET = 0x8000

# Filesystem pairings that must not be crossed. Keyed by label, value is the type the
# framework mounts. A label absent from this table is allowed any type, because a
# reserved slot has no framework to protect.
EXPECTED_FS = {
    "fs_meshcore": "spiffs",
    "fs_meshtastic": "littlefs",
    "fs_sniffer": "spiffs",
    "fs_reticulum": "spiffs",
    "fs_lorawan": "spiffs",
}


class FlashError(RuntimeError):
    pass


@dataclass
class Part:
    label: str
    ptype: str
    subtype: str
    offset: int
    size: int
    blank: bool
    line: int = 0


def parse_size(text: str) -> int:
    """Parse 0x10000, 4K, 1M, 4096, 4096K. Mirrors parseSize() in the C++."""
    t = text.strip()
    if not t:
        raise FlashError("empty size")
    mult = 1
    if t[-1] in "Kk":
        mult, t = 1024, t[:-1]
    elif t[-1] in "Mm":
        mult, t = 1024 * 1024, t[:-1]
    t = t.strip()
    base = 16 if t[:2].lower() == "0x" else 10
    try:
        return int(t, base) * mult
    except ValueError as exc:
        raise FlashError(f"cannot parse size {text!r}") from exc


def parse_csv(path: Path) -> list[Part]:
    parts: list[Part] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        f = [x.strip() for x in line.split(",")]
        if len(f) < 5:
            raise FlashError(f"{path.name}:{lineno}: fewer than five fields")
        blank = f[4] == ""
        try:
            offset = parse_size(f[3])
            size = 0 if blank else parse_size(f[4])
        except FlashError as exc:
            raise FlashError(f"{path.name}:{lineno}: {exc}") from exc
        parts.append(Part(f[0], f[1], f[2], offset, size, blank, lineno))
    if not parts:
        raise FlashError(f"{path.name}: no partitions")
    return parts


def validate(parts: list[Part], flash_size: int) -> None:
    """The geometry rules, in Python. Cross-checked against SlotPlan.cpp's."""
    for p in parts:
        if p.blank:
            continue
        if p.offset + p.size > flash_size:
            raise FlashError(
                f"{p.label} ends at 0x{p.offset + p.size:X}, past the "
                f"{flash_size // (1024 * 1024)}MB this board reports"
            )
        if p.ptype == "app" and p.size and p.offset % 0x10000:
            raise FlashError(
                f"{p.label} is at 0x{p.offset:X}, not 64KB aligned. The bootloader "
                "will refuse this and the board will look simply dead."
            )

    ordered = sorted(parts, key=lambda p: p.offset)
    for prev, cur in zip(ordered, ordered[1:]):
        if prev.blank:
            continue
        if cur.offset < prev.offset + prev.size:
            raise FlashError(
                f"{cur.label} at 0x{cur.offset:X} overlaps {prev.label} "
                f"(0x{prev.offset:X}+0x{prev.size:X})"
            )

    labels = [p.label for p in parts]
    if len(labels) != len(set(labels)):
        raise FlashError("duplicate partition labels")

    # The filesystem pairing. Distinct offsets are already covered by the overlap
    # check; what is not is the pairing. Meshtastic mounts LittleFS and MeshCore
    # mounts SPIFFS, and handing either side the other's type makes it format the
    # wrong one on boot and lose the other side's settings with no error anywhere.
    for label, want in EXPECTED_FS.items():
        if label not in labels:
            continue
        part = next(p for p in parts if p.label == label)
        if part.subtype != want:
            raise FlashError(
                f"{label} is declared {part.subtype!r}, expected {want!r}. "
                "Meshtastic mounts LittleFS and MeshCore mounts SPIFFS; handing "
                "either side the other's filesystem makes it format the wrong one on "
                "boot and lose the settings on the other side of the pair."
            )

    # Every app slot needs a settings store of its own.
    #
    # Checked as a *count* and as "no two slots share one", rather than by assuming the
    # filesystem for slot n is called `fs_<n>`. That naming assumption holds for the
    # shared layout and is false for the standalone one, where slot 0 is the sniffer and
    # therefore carries `fs_sniffer` -- and a check built on the assumption refused the
    # very table it was written to protect.
    app_slots = [p for p in parts if p.ptype == "app" and p.label.startswith("ota_")]
    fs_parts = [p for p in parts if p.label.startswith("fs_")]

    if len(fs_parts) != len(app_slots):
        raise FlashError(
            f"{len(app_slots)} app slot(s) but {len(fs_parts)} filesystem partition(s). "
            "Every slot needs its own: a framework with nowhere to keep its settings "
            "formats whatever it finds, and two frameworks sharing one filesystem is how "
            "a repeater's channel keys get reformatted by something an operator ran for "
            "five minutes"
        )

    if len({p.offset for p in fs_parts}) != len(fs_parts):
        raise FlashError(
            "two filesystem partitions overlap. Every slot's settings must be at its own "
            "address"
        )


def find_port(explicit: str | None) -> str:
    if explicit:
        return explicit
    if sys.platform.startswith("win"):
        found = _windows_serial_ports()
    else:
        found = [
            f"/dev/{n}"
            for n in ("ttyUSB0", "ttyACM0", "tty.usbserial-0001")
            if Path(f"/dev/{n}").exists()
        ]
    if not found:
        raise FlashError(
            "no serial port found. Pass --port explicitly, or check the cable: "
            "many USB-C cables carry power and no data."
        )
    return found[0]


def _windows_serial_ports() -> list[str]:
    try:
        import serial.tools.list_ports  # type: ignore
    except ImportError:
        return []
    return [p.device for p in serial.tools.list_ports.comports()]


def chip_flash_size(port: str) -> int:
    """Ask the chip how big it is instead of assuming.

    The V4 ships 16MB of external flash and a V3 does not, and a five-slot table on
    an 8MB board fails in a way that looks like a bad download rather than a wrong
    assumption. The running firmware checks the same thing at boot; this is the first
    half of the same defence.
    """
    if shutil.which("esptool") is None and shutil.which("esptool.py") is None:
        raise FlashError("esptool not found. Install it with: pip install esptool")
    tool = shutil.which("esptool") or shutil.which("esptool.py")
    proc = subprocess.run(
        [tool, "--chip", "esp32s3", "--port", port, "flash_id"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    blob = proc.stdout + proc.stderr
    m = re.search(r"Detected flash size:\s*(\d+)MB", blob) or re.search(
        r"flash size:\s*(\d+)MB", blob
    )
    if not m:
        raise FlashError(
            "could not read the flash size from the chip. Is it in bootloader mode?\n"
            + blob.strip()
        )
    return int(m.group(1)) * 1024 * 1024


def app_labels_for(table_name: str) -> dict[str, str]:
    """Map a framework's name to the app partition that holds it, for one table.

    `--app sniffer=...` is what every example in this repository says, and it never
    worked: the lookup was a plain match against partition labels, and no partition is
    called `sniffer`. The partitions are `ota_0`, `ota_1`, `ota_2`, and which of those
    holds the sniffer depends on the layout -- slot 2 in the shared table, slot 0 in the
    standalone one. So the examples were wrong *and* the tool could not accept its own
    documentation.

    Resolution comes from SlotPlan.hpp's `kRows` via gen_layouts, so the flasher cannot
    disagree with the firmware about which slot is the sniffer's. Partition labels are
    still accepted, because `ota_2` is what an operator reading the CSV will type.
    """
    import gen_layouts

    layout = next(
        (lay for name, lay, _ in gen_layouts.TABLES if name == f"{table_name}.csv"), None
    )
    if layout is None:
        return {}

    g = gen_layouts.Geometry(gen_layouts.HEADER.read_text(encoding="utf-8"))
    out: dict[str, str] = {}
    for index in range(g.slots_for(layout)):
        role = gen_layouts._role_for(g, layout, index)
        framework, _fs_label, _fs_type = g.labels[role]
        out[framework.lower()] = f"ota_{index}"
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--table", default="triboot", choices=TABLES, help="partition layout (default: triboot)")
    ap.add_argument("--bootloader", type=Path, required=True)
    ap.add_argument("--part-table-bin", type=Path, required=True)
    ap.add_argument("--otadata", type=Path)
    ap.add_argument(
        "--app",
        # Deliberately NOT type=Path. The value is `LABEL=PATH`, and argparse would hand
        # `main()` a Path object for the whole thing; the `"=" in item` test below then
        # raised `TypeError: argument of type 'WindowsPath' is not a container or
        # iterable`, so every invocation that named a slot crashed. Each half is turned
        # into a Path after the split.
        action="append",
        default=[],
        metavar="LABEL=PATH",
        help="application image for a slot, e.g. sniffer=.pio/build/.../firmware.bin",
    )
    ap.add_argument("--port")
    ap.add_argument("--baud", default="460800")
    ap.add_argument("--dry-run", action="store_true", help="validate and print, write nothing")
    args = ap.parse_args(argv)

    csv_path = PARTITION_DIR / f"{args.table}.csv"
    if not csv_path.is_file():
        raise FlashError(f"no such partition table: {csv_path}")

    try:
        parts = parse_csv(csv_path)
    except FlashError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"partition table: {csv_path.name}  ({len(parts)} partitions)")

    port = args.port
    if not args.dry_run and not port:
        port = find_port(None)

    flash_size = chip_flash_size(port) if port and not args.dry_run else 16 * 1024 * 1024
    print(f"flash size:      {flash_size // (1024 * 1024)}MB")

    try:
        validate(parts, flash_size)
    except FlashError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print("layout:          valid")

    by_label = {p.label: p for p in parts}
    # A framework name is accepted as well as a partition label, resolved through
    # SlotPlan.hpp so this cannot drift from the firmware's own idea of the layout.
    by_framework = app_labels_for(args.table)
    apps: dict[str, Path] = {}
    for item in args.app:
        if "=" not in item:
            raise FlashError(f"--app expects LABEL=PATH, got {item!r}")
        label, path = item.split("=", 1)
        label = by_framework.get(label.strip().lower(), label.strip())
        if label not in by_label:
            raise FlashError(
                f"no partition labelled {item.split('=', 1)[0]!r} in {csv_path.name}. "
                f"It has: {', '.join(sorted(by_label))}"
            )
        apps[label] = Path(path)

    # The bootloader and the partition table are NOT rows in the CSV, and this is the reason
    # the tool cannot read their addresses out of it.
    #
    # The bootloader is flashed at 0x0 out of band, and the partition table is written to
    # the fixed 4 KB sector at 0x8000 that the chip's bootloader reserves whether or not
    # the table says anything about it. A row for either is not merely redundant: a row
    # at 0x8000 is read as overlapping the table's own extent, and the generator refuses
    # the whole file.
    #
    # These two addresses are therefore constants here, and that is the only place in the
    # repository that knows them outside SlotPlan.hpp.
    plan: list[tuple[int, Path]] = [
        (BOOTLOADER_OFFSET, args.bootloader),
        (PARTITION_TABLE_OFFSET, args.part_table_bin),
    ]
    if "otadata" in by_label and args.otadata is not None:
        plan.append((by_label["otadata"].offset, args.otadata))

    for label, path in sorted(apps.items()):
        part = by_label[label]
        if part.size and path.is_file() and path.stat().st_size > part.size:
            raise FlashError(
                f"{path.name} is {path.stat().st_size} bytes but {label} only has "
                f"{part.size}. Shrink the image or pick a bigger slot."
            )
        plan.append((part.offset, path))

    for offset, path in plan:
        if not path.is_file():
            raise FlashError(f"missing file: {path}")

    print("\nwrite plan:")
    for offset, path in plan:
        print(f"  0x{offset:06X}  {path}")

    if not apps:
        print(
            "\nnote: no --app given, so only the bootloader and partition table will be "
            "written.\n      Pass --app sniffer=... to fill the slot, or "
            "--app meshcore=... --app meshtastic=...\n      to fill all three."
        )

    if args.dry_run:
        print("\ndry run: nothing written.")
        return 0

    if shutil.which("esptool") is None and shutil.which("esptool.py") is None:
        print("error: esptool not found. Install it with: pip install esptool", file=sys.stderr)
        return 2
    tool = shutil.which("esptool") or shutil.which("esptool.py")

    cmd = [
        tool,
        "--chip", "esp32s3",
        "--port", port,
        "--baud", args.baud,
        "--flash_mode", "dio",
        "--flash_freq", "80m",
        "--flash_size", f"{flash_size // (1024 * 1024)}MB",
        "write_flash",
        "-z",
    ]
    for offset, path in plan:
        cmd += [f"0x{offset:X}", str(path)]

    print("\nrunning esptool...")
    return subprocess.run(cmd).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except FlashError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
