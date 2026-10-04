#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerate the shipped partition tables from the code's geometry.

The geometry lives in firmware/include/sniffer/SlotPlan.hpp, as it does in the
bridge. It is not restated here: a second copy of these numbers is a second thing
to forget, and the test suite cross-checks the generated files against the header,
so a divergence fails `python tools/gate.py` rather than being discovered on a board
that will not boot.

    python tools/gen_layouts.py

Two tables are produced:

    triboot.csv       MeshCore + Meshtastic + Sniffer, two slots reserved
    snifferboot.csv   the sniffer alone, for flashing a board with nothing on it

The standalone table is not a toy. A board with no MeshCore image has no settings to
import and nothing to inherit, so the sniffer has to be useful on its own defaults
-- which it is, because everything it decodes other than the MeshCore channel
settings comes off the air.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEADER = ROOT / "firmware" / "include" / "sniffer" / "SlotPlan.hpp"
OUT_DIR = ROOT / "firmware" / "partitions"

# The tables this repository ships: (filename, layout, description).
#
# The layout matters as much as the slot count, because which filesystem belongs to
# which slot does. Generating the standalone table from the canonical slot order paired
# the sniffer's app partition with fs_meshcore -- which would let a MeshCore image
# flashed into that slot adopt the sniffer's settings, and which
# `validateForSniffer()` correctly rejects.
TABLES = [
    ("triboot.csv", "Shared", "MeshCore, Meshtastic and the sniffer, two slots reserved"),
    ("snifferboot.csv", "Standalone", "the sniffer alone, for a board with nothing else on it"),
]


def _eval_int(expr: str) -> int | None:
    """Evaluate an integer arithmetic expression, or return None.

    A hand-written recursive-descent parser rather than `eval`, and the character
    set is restricted to digits and `+ - * / ( )`. Anything else -- a name, a cast,
    a function call -- returns None, so an expression this does not understand is
    left unresolved rather than guessed at.
    """
    s = expr.strip()
    pos = 0

    def skip() -> None:
        nonlocal pos
        while pos < len(s) and s[pos].isspace():
            pos += 1

    def primary() -> int | None:
        nonlocal pos
        skip()
        if pos >= len(s):
            return None
        if s[pos] == "(":
            pos += 1
            v = expr_or()
            skip()
            if pos >= len(s) or s[pos] != ")":
                return None
            pos += 1
            return v
        start = pos
        while pos < len(s) and s[pos].isdigit():
            pos += 1
        if start == pos:
            return None
        return int(s[start:pos], 10)

    def term() -> int | None:
        nonlocal pos
        v = primary()
        if v is None:
            return None
        while True:
            skip()
            if pos < len(s) and s[pos] in "*/":
                op = s[pos]
                pos += 1
                rhs = primary()
                if rhs is None or rhs == 0:
                    return None
                v = v * rhs if op == "*" else v // rhs
                continue
            return v

    def expr_or() -> int | None:
        nonlocal pos
        v = term()
        if v is None:
            return None
        while True:
            skip()
            if pos < len(s) and s[pos] in "+-":
                op = s[pos]
                pos += 1
                rhs = term()
                if rhs is None:
                    return None
                v = v + rhs if op == "+" else v - rhs
                continue
            return v

    value = expr_or()
    if value is None:
        return None
    skip()
    return value if pos == len(s) else None


def read_constants(header: str) -> dict[str, int]:
    """Collect every `constexpr <type> <name> = <expr>;` in the header.

    The expressions are allowed to reference other constants and to be arithmetic
    over literals -- `kFirstSlotOffset` is `kCoredumpOffset + kCoredumpSize` and
    `kDefaultFlashBytes` is `16u * 1024u * 1024u`. Both are evaluated here rather
    than pattern-matched, because those derivations are the point: capacity is a
    subtraction rather than a moving target precisely because the coredump sits
    below the slots.

    Resolution is iterative -- literals and literal arithmetic first, then
    expressions over names already known -- so a forward reference resolves the same
    way a C++ compiler would.
    """
    pattern = re.compile(r"constexpr\s+[\w:<>\s*]*?\s(\w+)\s*=\s*([^;]+);", re.MULTILINE)
    raw: dict[str, str] = {}
    for m in pattern.finditer(header):
        name = m.group(1)
        expr = m.group(2).split("//")[0].strip()
        if name and expr:
            raw.setdefault(name, expr)

    known: dict[str, int] = {}
    pending: dict[str, str] = {}

    def literal_or_arith(expr: str) -> int | None:
        # Drop C++ integer suffixes (`16u`, `1024UL`) before parsing. Anchored to a
        # complete literal so it cannot eat a hex digit.
        e = re.sub(r"(0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]+\b", r"\1", expr.strip()).strip()
        if re.fullmatch(r"0[xX][0-9A-Fa-f]+", e):
            return int(e, 16)
        if re.fullmatch(r"[0-9]+", e):
            return int(e, 10)
        return _eval_int(e)

    for name, expr in raw.items():
        value = literal_or_arith(expr)
        if value is None:
            pending[name] = expr
        else:
            known[name] = value

    for _ in range(16):
        progressed = False
        for name, expr in list(pending.items()):
            # Substitute every name we already know, then try again.
            substituted = expr
            for other, value in sorted(known.items(), key=lambda kv: -len(kv[0])):
                substituted = re.sub(rf"\b{re.escape(other)}\b", str(value), substituted)
            value = _eval_int(substituted)
            if value is not None:
                known[name] = value
                del pending[name]
                progressed = True
        if not progressed:
            break

    return known


class Constants:
    def __init__(self, header: str) -> None:
        self.values = read_constants(header)

    def __call__(self, name: str) -> int:
        if name not in self.values:
            raise SystemExit(
                f"error: {name} not found or not resolvable in {HEADER.name}. "
                "The geometry this script generates from has changed."
            )
        return self.values[name]


class Geometry:
    def __init__(self, header: str) -> None:
        get = Constants(header)
        self.stride = get("kSlotStrideBytes")
        self.app = get("kSlotAppBytes")
        self.fs = get("kSlotFsBytes")
        self.first = get("kFirstSlotOffset")
        self.alignment = get("kAppAlignment")
        self.flash = get("kDefaultFlashBytes")
        self.coredump_offset = get("kCoredumpOffset")
        self.coredump_size = get("kCoredumpSize")

        # kFirstSlotOffset is derived from the coredump in the header. Recomputing it
        # here from the same constants is the cross-check that the header's own
        # derivation is right; if it is not, the generated table would disagree with
        # the firmware's idea of where slot 0 is.
        if self.coredump_offset + self.coredump_size != self.first:
            raise SystemExit(
                "error: kFirstSlotOffset in the header does not follow from the coredump "
                f"({self.coredump_offset:#x} + {self.coredump_size:#x} != {self.first:#x})"
            )

        self.k_sniffer_slot = get("kSnifferSlot")
        self.labels = self._roles(header)
        self.layouts = self._layouts(header)

    def _roles(self, header: str) -> list[tuple[str, str, str]]:
        """The slot order, taken from the header's kRows table."""
        block = re.search(r"inline constexpr RoleRow kRows\[\] = \{(.*?)\n\};", header, re.S)
        if not block:
            raise SystemExit(f"error: kRows not found in {HEADER.name}")
        order: list[tuple[str, str, str]] = []
        for line in block.group(1).splitlines():
            m = re.match(r'\s*\{\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\}', line)
            if m:
                order.append((m.group(1), m.group(2), m.group(3)))
        if len(order) < 3:
            raise SystemExit(f"error: expected at least three roles, found {len(order)}")
        return order

    def _layouts(self, header: str) -> dict[str, dict[str, int]]:
        """Per-layout slot count, and which slot the sniffer occupies.

        Parsed from `sharedSlots()` / `standaloneSlots()` and `kSnifferSlot` rather
        than restated here, so the generator cannot disagree with the firmware about
        how many slots a layout has. The standalone layout's sniffer index is read
        from `snifferSlotIn`'s own literal, which is the only one that is not a named
        constant.
        """
        layouts: dict[str, dict[str, int]] = {}
        for name, fn in (("Shared", "sharedSlots"), ("Standalone", "standaloneSlots")):
            m = re.search(rf"constexpr std::uint8_t {fn}\(\) \{{ return (\d+); \}}", header)
            if not m:
                raise SystemExit(f"error: {fn}() not found in {HEADER.name}")
            layouts[name] = {"slots": int(m.group(1))}

        sniffer = re.search(
            r"constexpr std::uint8_t snifferSlotIn\(Layout layout\) \{\s*"
            r"return layout == Layout::Standalone \? (\d+) : kSnifferSlot;",
            header,
            re.S,
        )
        if not sniffer:
            raise SystemExit(
                f"error: the standalone branch of snifferSlotIn() not found in {HEADER.name}"
            )
        layouts["Standalone"]["sniffer"] = int(sniffer.group(1))
        layouts["Shared"]["sniffer"] = self.k_sniffer_slot

        for name, info in layouts.items():
            if info["sniffer"] >= info["slots"]:
                raise SystemExit(
                    f"error: {name} declares {info['slots']} slots but puts the sniffer in "
                    f"slot {info['sniffer']}"
                )
        return layouts

    def slots_for(self, layout: str) -> int:
        return self.layouts[layout]["slots"]

    def sniffer_slot_for(self, layout: str) -> int:
        return self.layouts[layout]["sniffer"]

    def slot_offset(self, index: int) -> int:
        return self.first + index * self.stride

    def fs_offset(self, index: int) -> int:
        return self.slot_offset(index) + self.app

    def max_slots(self, flash: int) -> int:
        return max(0, (flash - self.first) // self.stride)


# Which row of kRows occupies a slot in a layout. Mirrors `roleAt()` in
# SlotPlan.hpp: the standalone layout puts the sniffer in slot zero, the shared layout
# puts the n-th framework in slot n.
#
# Parsed from the header rather than written here, because getting this wrong is what
# put `fs_meshcore` beside the sniffer's app partition in the first version of
# snifferboot.csv.
def _role_for(g: Geometry, layout: str, index: int) -> int:
    if layout == "Standalone":
        # A kRows row is (role, fsLabel, fsType), so the role is the first field --
        # matching on fsLabel here would look for "fs_sniffer" in a field holding
        # "sniffer" and find nothing.
        for i, row in enumerate(g.labels):
            if row[0] == "sniffer":
                return i
        raise SystemExit(f"error: no row for the sniffer in {HEADER.name}")
    return index


def render(g: Geometry, layout: str, description: str) -> str:
    slots = g.slots_for(layout)
    sniffer_slot = g.sniffer_slot_for(layout)
    if slots > len(g.labels):
        raise SystemExit(f"error: {slots} slots requested but the header defines {len(g.labels)}")

    out: list[str] = []
    a = out.append

    def hx(value: int) -> str:
        # Uppercase hex, matching what the firmware's own renderer emits. The
        # generated file and the header-generated one have to look the same or a diff
        # between them means nothing.
        return f"0x{value:X}"

    a(f"# LoRa sniffer -- Heltec WiFi LoRa 32 V4, {layout} layout, {slots} slots. {description}")
    a("#")
    a("# GENERATED by tools/gen_layouts.py from firmware/include/sniffer/SlotPlan.hpp.")
    a("# Edit the geometry there, not here; then run:  python tools/gen_layouts.py")
    a("#")
    a("# Slot *addresses* are fixed and append-only: slot n lives at the same place")
    a("# whether this table declares one slot or five, so it can be rewritten in")
    a("# place to add a framework without ever moving one that already holds")
    a("# firmware. That is the whole reason growth is safe here.")
    a("#")
    a("# Slot *contents* differ per layout. In the shared layout slot n holds the")
    a("# n-th framework; in the standalone layout slot 0 holds the sniffer and so")
    a("# carries fs_sniffer rather than fs_meshcore. Getting that pairing wrong is")
    a("# not cosmetic: a MeshCore image flashed into a slot labelled fs_sniffer")
    a("# would adopt this firmware's settings.")
    a("#")
    for i in range(slots):
        label, fs_label, _ = g.labels[_role_for(g, layout, i)]
        note = "  <-- this firmware" if i == sniffer_slot else ""
        # rstrip: the alignment padding is only there to make the comment column line up,
        # and trailing spaces in a generated file are noise a reviewer has to notice.
        a(f"#   ota_{i} / {fs_label:<13} {label:<11}{note}".rstrip())
    if slots < len(g.labels):
        a("#")
        for i in range(slots, len(g.labels)):
            label, fs_label, _ = g.labels[_role_for(g, "Shared", i)]
            a(f"#   ota_{i}                      reserved, {fs_label} not flashed here")
    a("#")
    a("# Meshtastic mounts LittleFS and MeshCore mounts SPIFFS. Handing either side")
    a("# the other's filesystem type makes it format the wrong one on boot and lose")
    a("# the settings of the other side of the pair, with no error anywhere.")
    a("#")
    a("# Every app offset is 64KB aligned. The bootloader refuses a misaligned app")
    a("# partition and reports nothing, so a board with one simply looks dead.")
    a("#")
    a("# Validate with: python tools/gate.py")
    a("")

    # The bootloader and the partition table are NOT rows in this file.
    #
    # The bootloader is flashed at 0x0 by convention, and the partition table occupies
    # the single 4 KB sector at 0x8000 whether or not a row says so. Listing either one
    # is not merely redundant: a row at 0x8000 is read as *overlapping* the table's own
    # extent, and `gen_esp32part.py` refuses the table with "first partition offset 0x0
    # overlaps end of partition table 0x9000". This table declared a 0xC000-byte
    # partition_tbl row there and no build of any env could get past it.
    a("# 0x0000  bootloader, flashed out of band and not described here")
    a("# 0x8000  this table, one 4 KB sector, not described here either")
    a("# 0x9000  first partition below")
    a("")
    a("otadata        , data , ota      , 0x14000, 0x2000,")
    a("nvs            , data , nvs      , 0x16000, 0xA000,")
    a(f"coredump       , data , coredump , {hx(g.coredump_offset)}, {hx(g.coredump_size)},")
    a("")

    for i in range(slots):
        _, fs_label, fs_type = g.labels[_role_for(g, layout, i)]
        off = g.slot_offset(i)
        if off % g.alignment:
            raise SystemExit(f"error: ota_{i} at {off:#x} is not {g.alignment:#x} aligned")
        a(f"ota_{i}          , app  , ota_{i}    , {hx(off)}, {hx(g.app)},")
        a(f"{fs_label:<14} , data , {fs_type:<9}, {hx(g.fs_offset(i))}, {hx(g.fs)},")

    used = g.fs_offset(slots - 1) + g.fs if slots else g.first
    if g.flash > used:
        a("")
        a(f"# {g.flash - used} bytes free after slot {slots - 1}")

    return "\n".join(out) + "\n"


def main() -> int:
    header = HEADER.read_text(encoding="utf-8")
    g = Geometry(header)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, layout, description in TABLES:
        slots = g.slots_for(layout)
        if slots > g.max_slots(g.flash):
            print(
                f"skipping {name}: {slots} slots do not fit {g.flash // (1024 * 1024)}MB",
                file=sys.stderr,
            )
            continue
        text = render(g, layout, description)
        (OUT_DIR / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {name}  ({layout}, {slots} slots, {len(text.splitlines())} lines)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
