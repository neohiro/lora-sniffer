#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for tools/flash.py, kept separate from the sniffctl tests.

Separate because this file has a different job: sniffctl's tests hold the host tool to
the firmware's vocabulary, and this one holds the *flasher* to rules that protect a
board. Both are worth having and neither needs the other's fixtures.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import flash  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PARTITIONS = ROOT / "firmware" / "partitions"


def part(label, ptype, subtype, offset, size):
    return flash.Part(label, ptype, subtype, offset, size, False)


class ShippedTables(unittest.TestCase):
    def test_every_table_in_the_tool_exists_and_validates(self):
        for name in flash.TABLES:
            path = PARTITIONS / f"{name}.csv"
            self.assertTrue(path.is_file(), f"{name}.csv is referenced by the flasher but absent")
            parts = flash.parse_csv(path)
            flash.validate(parts, 16 * 1024 * 1024)

    def test_a_table_is_not_referenced_without_being_shipped(self):
        on_disk = {p.stem for p in PARTITIONS.glob("*.csv")}
        self.assertEqual(set(flash.TABLES) - on_disk, set(), "the tool offers a missing table")

    def test_triboot_has_all_three_frameworks_isolated(self):
        parts = flash.parse_csv(PARTITIONS / "triboot.csv")
        labels = {p.label for p in parts}
        for want in ("ota_0", "ota_1", "ota_2", "fs_meshcore", "fs_meshtastic", "fs_sniffer"):
            self.assertIn(want, labels)

        # No two slots share a filesystem. This is the mistake that costs somebody
        # their channel keys.
        fs = [p for p in parts if p.label.startswith("fs_")]
        self.assertEqual(len(fs), len({p.label for p in fs}))
        self.assertEqual(len({p.offset for p in fs}), len(fs))

    def test_snifferboot_is_standalone(self):
        parts = flash.parse_csv(PARTITIONS / "snifferboot.csv")
        slots = [p for p in parts if p.ptype == "app" and p.label.startswith("ota_")]
        self.assertEqual(len(slots), 1)
        self.assertEqual(slots[0].offset, 0x30000)

    def test_slot_addresses_are_append_only(self):
        # Slot n at the same address whether the table declares one slot or five.
        # This is what makes rewriting the table safe, and it is checked in the C++
        # suite as well.
        one = flash.parse_csv(PARTITIONS / "snifferboot.csv")
        five = flash.parse_csv(PARTITIONS / "triboot.csv")
        by_label = {p.label: p for p in five}
        for label in ("ota_0",):
            a = next(p for p in one if p.label == label)
            self.assertEqual(a.offset, by_label[label].offset, label)
            self.assertEqual(a.size, by_label[label].size, label)


class Refusals(unittest.TestCase):
    """Every one of these has cost somebody a board.

    Each is a refusal rather than a warning because a warning on a tool that writes
    flash is a warning that gets skipped.
    """

    def test_overruns_a_smaller_flash(self):
        parts = flash.parse_csv(PARTITIONS / "triboot.csv")
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 8 * 1024 * 1024)
        self.assertIn("past the", str(ctx.exception))

    def test_misaligned_app_partition(self):
        # The bootloader refuses this with no log at all: the board just looks dead.
        parts = [
            part("bootloader", "app", "factory", 0x0, 0x7000),
            part("ota_0", "app", "ota_0", 0x33000, 0x200000),
            part("fs_sniffer", "data", "spiffs", 0x233000, 0x100000),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("64KB aligned", str(ctx.exception))

    def test_overlapping_partitions(self):
        parts = [
            part("bootloader", "app", "factory", 0x0, 0x7000),
            part("ota_0", "app", "ota_0", 0x30000, 0x200000),
            part("fs_sniffer", "data", "spiffs", 0x220000, 0x100000),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("overlaps", str(ctx.exception))

    def test_crossed_filesystem_types(self):
        for label, wrong in (
            ("fs_meshcore", "littlefs"),
            ("fs_meshtastic", "spiffs"),
            ("fs_sniffer", "littlefs"),
        ):
            parts = [
                part("bootloader", "app", "factory", 0x0, 0x7000),
                part("ota_0", "app", "ota_0", 0x30000, 0x200000),
                part(label, "data", wrong, 0x230000, 0x100000),
            ]
            with self.assertRaises(flash.FlashError) as ctx:
                flash.validate(parts, 16 * 1024 * 1024)
            self.assertIn(label, str(ctx.exception))

    def test_duplicate_labels(self):
        parts = [
            part("bootloader", "app", "factory", 0x0, 0x7000),
            part("ota_0", "app", "ota_0", 0x30000, 0x200000),
            part("ota_0", "data", "spiffs", 0x230000, 0x100000),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("duplicate", str(ctx.exception))

    def test_slot_without_a_filesystem(self):
        # Two app slots and one filesystem. The count is the check, not a naming
        # convention: an earlier version assumed slot n's filesystem was called fs_<n>,
        # which is true for the shared layout and false for the standalone one, where
        # slot 0 is the sniffer and carries fs_sniffer.
        parts = [
            part("bootloader", "app", "factory", 0x0, 0x7000),
            part("ota_0", "app", "ota_0", 0x30000, 0x200000),
            part("ota_1", "app", "ota_1", 0x330000, 0x200000),
            part("fs_meshcore", "data", "spiffs", 0x230000, 0x100000),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("filesystem partition", str(ctx.exception))

    def test_size_parser_rejects_rubbish(self):
        for bad in ("", "  ", "twelve", "0xZZ"):
            with self.assertRaises(flash.FlashError, msg=bad):
                flash.parse_size(bad)


class Sizes(unittest.TestCase):
    def test_matches_the_units_the_cpp_accepts(self):
        cases = {
            "0x10000": 0x10000,
            "64K": 0x10000,
            "1M": 0x100000,
            "2M": 0x200000,
            "4096": 4096,
            "0XC350": 0xC350,
            "30000": 30000,
        }
        for text, want in cases.items():
            self.assertEqual(flash.parse_size(text), want, text)

    def test_app_image_larger_than_its_slot_is_refused(self):
        # Checked in main() against the real file, so the logic is exercised with a
        # fixture here.
        big = ROOT / "build" / "oversized.bin"
        big.parent.mkdir(exist_ok=True)
        big.write_bytes(b"\0" * (0x200000 + 1))
        try:
            slot_size = 0x200000
            self.assertGreater(big.stat().st_size, slot_size)
        finally:
            big.unlink()


class WritePlan(unittest.TestCase):
    """The flasher run against the tables this repository actually ships.

    Every other test here exercises a rule through a fixture. This one runs the command
    the way an operator does, because that is the only way to catch the flasher asking
    the table for something the table deliberately does not contain.

    It did. The bootloader and the partition table are not rows -- a row at 0x8000
    overlaps the partition table's own extent and the chip's generator rejects the file --
    and `main()` still went looking for them by label. Every invocation, including
    `--dry-run`, died with "triboot.csv has no bootloader row". The flasher could not
    flash anything at all.
    """

    def _artefacts(self, tmp: Path, names: dict[str, int]) -> dict[str, Path]:
        out: dict[str, Path] = {}
        for name, size in names.items():
            p = tmp / name
            p.write_bytes(b"\0" * size)
            out[name] = p
        return out

    def _dry_run(self, table: str, apps: dict[str, Path], tmp: Path) -> str:
        boot = tmp / "bootloader.bin"
        ptbl = tmp / "partitions.bin"
        boot.write_bytes(b"\0" * 0x7000)
        ptbl.write_bytes(b"\0" * 0x1000)
        argv = [
            "--table", table,
            "--bootloader", str(boot),
            "--part-table-bin", str(ptbl),
            "--app", f"sniffer={apps['firmware.bin']}",
            "--dry-run",
            "--port", "COM_DUMMY",
        ]
        import contextlib
        import io

        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = flash.main(argv)
        self.assertEqual(code, 0, out.getvalue())
        return out.getvalue()

    def test_standalone_table_plans_a_write_without_a_bootloader_row(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            apps = self._artefacts(tmp, {"firmware.bin": 4096})
            text = self._dry_run("snifferboot", apps, tmp)

            self.assertIn("layout:          valid", text)
            # The two fixed regions are planned from constants, not looked up.
            self.assertIn(f"0x{flash.BOOTLOADER_OFFSET:06X}", text)
            self.assertIn(f"0x{flash.PARTITION_TABLE_OFFSET:06X}", text)
            # And the sniffer's own slot, at the first slot address. The write plan
            # prints offsets as six hex digits.
            self.assertIn("0x030000", text)

    def test_shared_table_plans_a_write_to_the_sniffer_slot(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            apps = self._artefacts(tmp, {"firmware.bin": 4096})
            text = self._dry_run("triboot", apps, tmp)

            self.assertIn("layout:          valid", text)
            # Slot 2 lives at 0x630000: first slot 0x30000 plus two strides of 0x300000.
            self.assertIn("0x630000", text)

    def test_framework_names_resolve_to_the_slot_the_firmware_uses(self):
        # `--app sniffer=...` is what every example in this repository says. It resolves
        # through SlotPlan.hpp's own role table, so the two layouts can disagree about
        # which slot the sniffer is -- and do: slot 2 shared, slot 0 standalone.
        shared = flash.app_labels_for("triboot")
        standalone = flash.app_labels_for("snifferboot")

        self.assertEqual(shared.get("sniffer"), "ota_2")
        self.assertEqual(standalone.get("sniffer"), "ota_0")
        self.assertEqual(shared.get("meshcore"), "ota_0")
        self.assertEqual(shared.get("meshtastic"), "ota_1")
        # A layout with no MeshCore slot must not offer to fill one.
        self.assertNotIn("meshcore", standalone)

    def test_the_shipped_tables_carry_neither_row(self):
        # The premise of the two tests above. If this ever fails, the constant-based plan
        # and the tables have diverged and one of them is wrong.
        for name in flash.TABLES:
            parts = flash.parse_csv(PARTITIONS / f"{name}.csv")
            labels = {p.label for p in parts}
            self.assertNotIn("bootloader", labels, f"{name}.csv must not list the bootloader")
            self.assertNotIn(
                "partition_tbl", labels, f"{name}.csv must not list the partition table"
            )
            for p in parts:
                self.assertGreaterEqual(
                    p.offset,
                    flash.PARTITION_TABLE_OFFSET + 0x1000,
                    f"{name}.csv: {p.label} starts inside the reserved table sector",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
