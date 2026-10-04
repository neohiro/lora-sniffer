#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repository hygiene.

The boring things, which are exactly the things that pass on the machine that
committed and fail on a fresh clone somewhere else. Every check here has been written
after watching that happen.

The line-ending one is the reason .gitattributes carries `eol=lf` on everything: git's
default `core.autocrlf` on Windows rewrites every LF file to CRLF on checkout, which
contradicts .editorconfig and makes this file fail on a Windows clone while passing on
the machine that committed. The worst possible way to discover a line-ending problem.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEXT_SUFFIXES = {
    ".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".py", ".ini", ".csv", ".txt",
    ".yml", ".yaml", ".json", ".gitignore", ".gitattributes", ".editorconfig",
}

SUFFIXLESS_TEXT = {"Makefile", "LICENSE", "README.md"}

SKIP_DIRS = {".git", "build", ".pio", "__pycache__", ".pytest_cache", ".ruff_cache", ".venv"}

# Files that carry a licence header. The generated partition tables do not, because
# they are generated and the header would be lost on the next regeneration.
NO_HEADER_NEEDED = {".csv"}


def tracked_files() -> list[Path]:
    out: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in SUFFIXLESS_TEXT:
            continue
        out.append(path)
    return sorted(out)


def guarded_regions(src: str, macro: str) -> list[str]:
    """The bodies of every `#if <macro>` block in a C++ source.

    Preprocessor matching is a stack, not a regex: a `#endif` closes the innermost open
    `#if`, and a flat scan gets this wrong as soon as a guarded block contains a nested
    one. Returns the text inside each block that mentions `macro`, outermost-only
    included so a caller sees the whole guarded region.
    """
    regions: list[str] = []
    # Each entry is [macro_matched, depth, [lines]]
    stack: list[list] = []

    for line in src.splitlines():
        stripped = line.strip()

        if stripped.startswith("#if"):
            matched = macro in stripped
            if stack:
                # Nested: inherit whether we are inside a guarded region.
                matched = matched or stack[-1][0]
            stack.append([matched, 1 if not stack else stack[-1][1] + 1, []])
            continue

        if stripped.startswith("#endif") and stack:
            frame = stack.pop()
            if frame[0]:
                regions.append("\n".join(frame[2]))
            if stack and not frame[0]:
                stack[-1][2].append(line)
            continue

        if stripped.startswith("#else") or stripped.startswith("#elif"):
            if stack:
                if stack[-1][0]:
                    regions.append("\n".join(stack[-1][2]))
                    stack[-1][2] = []
                continue

        if stack:
            stack[-1][2].append(line)

    return regions


class Includes(unittest.TestCase):
    """Every file that uses a C string function includes <cstring> itself.

    `strcmp`, `strlen` and friends live in `<cstring>`. A translation unit that uses one
    without including it compiles on whichever machine happened to include `<cstring>`
    first, and fails on the others.

    `tests/test_rf_plan.cpp` did exactly this: it used `strcmp()` and got the declaration
    transitively from a header it included. Every Windows and macOS build passed and the
    Linux runner failed with "'strcmp' was not declared in this scope". A build matrix
    whose members disagree is only useful if something acts on the disagreement, so this
    is the something.
    """

    FUNCTIONS = ("strcmp", "strncmp", "strlen", "strstr", "strchr", "strrchr", "memcmp")

    def _sources(self):
        for sub in ("firmware/src", "firmware/include/sniffer", "firmware/src/radio", "tests"):
            directory = ROOT / sub
            if not directory.is_dir():
                continue
            for path in sorted(directory.iterdir()):
                if path.suffix in {".cpp", ".hpp"} and path.is_file():
                    yield sub, path

    def test_users_of_c_string_functions_include_cstring(self):
        offenders = []
        for sub, path in self._sources():
            text = path.read_text(encoding="utf-8")
            if "#include <cstring>" in text or "#include <string.h>" in text:
                continue
            # Only flag a *call*, not a mention in a comment or a member named strcmp.
            body = "\n".join(
                line for line in text.splitlines() if not line.lstrip().startswith("//")
            )
            for name in self.FUNCTIONS:
                if re.search(rf"(?<![A-Za-z0-9_:]){name}\s*\(", body):
                    offenders.append(f"{sub}/{path.name}: {name}()")
                    break
        self.assertEqual(
            offenders,
            [],
            "uses a C string function without including <cstring>: "
            + ", ".join(offenders),
        )


class LineEndings(unittest.TestCase):
    def test_no_crlf(self):
        offenders = []
        for path in tracked_files():
            raw = path.read_bytes()
            if b"\r\n" in raw:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            offenders, [], f"CRLF found; .gitattributes pins eol=lf: {offenders}"
        )

    def test_final_newline(self):
        offenders = []
        for path in tracked_files():
            raw = path.read_bytes()
            if raw and not raw.endswith(b"\n"):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [], f"missing final newline: {offenders}")

    def test_no_trailing_whitespace_in_code(self):
        # Markdown is excluded: two trailing spaces are a hard line break there.
        offenders = []
        for path in tracked_files():
            if path.suffix.lower() in {".md"} or path.name == "Makefile":
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if line != line.rstrip():
                    offenders.append(f"{path.relative_to(ROOT)}:{n}")
                    break
        self.assertEqual(offenders, [], f"trailing whitespace: {offenders}")

    def test_no_tabs_in_cpp(self):
        offenders = []
        for path in tracked_files():
            if path.suffix.lower() not in {".c", ".cc", ".cpp", ".h", ".hpp"}:
                continue
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "\t" in line:
                    offenders.append(f"{path.relative_to(ROOT)}:{n}")
        self.assertEqual(offenders, [], f"tabs in C++: {offenders}")


class LicenceHeaders(unittest.TestCase):
    def test_sources_carry_the_spdx_line(self):
        offenders = []
        for path in tracked_files():
            suffix = path.suffix.lower()
            if suffix not in {".c", ".cc", ".cpp", ".h", ".hpp", ".py"}:
                continue
            head = path.read_text(encoding="utf-8")[:200]
            if "SPDX-License-Identifier: MIT" not in head:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(
            offenders, [], f"missing SPDX header: {offenders}"
        )


class Consistency(unittest.TestCase):
    """Things that must agree across files, checked mechanically.

    Each of these is a class of bug that produces a confusing failure rather than an
    obvious one, which is why they are worth asserting rather than eyeballing.
    """

    def test_generated_tables_say_they_are_generated(self):
        # A partition table with no provenance is one somebody will hand-edit.
        for path in (ROOT / "firmware" / "partitions").glob("*.csv"):
            text = path.read_text(encoding="utf-8")
            self.assertIn(
                "GENERATED by tools/gen_layouts.py", text, f"{path.name} lacks provenance"
            )
            self.assertIn("firmware/include/sniffer/SlotPlan.hpp", text, path.name)
            self.assertIn("python tools/gate.py", text, f"{path.name} does not say how to check it")

    def test_generated_tables_match_a_fresh_generation(self):
        # Regenerating must be a no-op. If it is not, the committed tables and the
        # geometry in the header have drifted apart.
        import subprocess

        proc = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "gen_layouts.py")],
            capture_output=True,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

        # gen_layouts rewrites in place with newline="\n", so the point of the check
        # is that nothing changed. Compare against a fresh render instead, which
        # catches a geometry change even if the bytes happen to match.
        sys.path.insert(0, str(ROOT / "tools"))
        import gen_layouts

        header = (ROOT / "firmware" / "include" / "sniffer" / "SlotPlan.hpp").read_text(
            encoding="utf-8"
        )
        geometry = gen_layouts.Geometry(header)
        for name, slots, description in gen_layouts.TABLES:
            path = ROOT / "firmware" / "partitions" / name
            self.assertEqual(
                path.read_text(encoding="utf-8"),
                gen_layouts.render(geometry, slots, description),
                f"{name} does not match the geometry in SlotPlan.hpp",
            )

    def test_gate_driver_lists_every_firmware_source(self):
        # A source file missing from the gate's list compiles on nobody's machine.
        gate = (ROOT / "tools" / "gate.py").read_text(encoding="utf-8")
        for path in sorted((ROOT / "firmware" / "src").glob("*.cpp")):
            self.assertIn(
                path.name, gate, f"{path.name} is not in gate.py's FIRMWARE_SRC"
            )

    def test_gate_driver_lists_every_test(self):
        gate = (ROOT / "tools" / "gate.py").read_text(encoding="utf-8")
        for path in sorted((ROOT / "tests").glob("*.py")):
            if path.name.startswith("test_"):
                self.assertIn(path.name, gate, f"{path.name} is not run by the gate")
        for path in sorted((ROOT / "tests").glob("test_*.cpp")):
            self.assertIn(path.name, gate, f"{path.name} is not compiled by the gate")

    def test_every_suite_is_registered(self):
        main = (ROOT / "tests" / "main.cpp").read_text(encoding="utf-8")
        suites = (ROOT / "tests" / "suites.hpp").read_text(encoding="utf-8")
        declared = set(re.findall(r"void (suite_\w+)\(", suites))
        # Match the call, not a specific arity: `suite_partition_csv(tables.data(), n)`
        # takes arguments, and a regex that only recognised `suite_x();` reported it as
        # dead while it ran on every invocation.
        called = set(re.findall(r"^\s*(suite_\w+)\(", main, re.M))
        self.assertEqual(
            declared - called,
            set(),
            "a suite is declared but never run, which is a silently dead test file",
        )

    def test_platformio_points_at_a_table_that_exists(self):
        ini = (ROOT / "firmware" / "platformio.ini").read_text(encoding="utf-8")
        for match in re.findall(r"partitions/(\w+)\.csv", ini):
            self.assertTrue(
                (ROOT / "firmware" / "partitions" / f"{match}.csv").is_file(),
                f"platformio.ini references {match}.csv, which does not exist",
            )

    def test_documented_paths_exist(self):
        # Every docs/ link in the README has to resolve, because a broken link in a
        # README is the first thing a new visitor meets.
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for match in re.findall(r"\]\((docs/[A-Za-z0-9._/-]+)\)", readme):
            self.assertTrue((ROOT / match).is_file(), f"README links to a missing {match}")

    def test_documentation_covers_every_public_header(self):
        docs = "\n".join(
            p.read_text(encoding="utf-8") for p in sorted((ROOT / "docs").glob("*.md"))
        )
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        for path in sorted((ROOT / "firmware" / "include" / "sniffer").glob("*.hpp")):
            name = path.stem
            self.assertTrue(
                name in docs or name in readme,
                f"{name}.hpp is public and is mentioned in neither the docs nor the README",
            )


class Sizing(unittest.TestCase):
    def test_every_fixed_table_is_bounded(self):
        # The device list and the capture ring are the two tables that grow if asked,
        # and both are capacity-parameterised precisely so the working set is exact.
        table = (ROOT / "firmware" / "include" / "sniffer" / "DeviceTable.hpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("static_assert(kCapacity > 0", table)

        ring = (ROOT / "firmware" / "include" / "sniffer" / "Transport.hpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("static_assert(kCapacity > 0", ring)

        memory = (ROOT / "firmware" / "include" / "sniffer" / "MemoryBudget.hpp").read_text(
            encoding="utf-8"
        )
        self.assertIn("workingSetBytes", memory)

    def test_the_transmit_gate_is_a_property_not_a_comment(self):
        header = (ROOT / "firmware" / "include" / "sniffer" / "TxLockout.hpp").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "constexpr bool mayTransmit() { return false; }",
            header,
            "the RX-only guarantee must be an unconditional constexpr, not a runtime check",
        )
        self.assertIn("SNIFFER_TX_CAPABLE", header)

    def test_only_the_transmit_path_is_behind_the_tx_flag(self):
        # The flag that removes beacon transmission must not also remove the radio.
        #
        # The whole radio file was once wrapped in `#if SNIFFER_TX_CAPABLE`, on the
        # reasoning that a sniffer only receives. The default build -- the one everybody
        # flashes, with the flag at 0 -- therefore linked no radio at all: begin()
        # returned false and the device captured nothing, while looking in every other
        # respect like a working sniffer.
        src = (ROOT / "firmware" / "src" / "radio" / "Sx1262Promiscuous.cpp").read_text(
            encoding="utf-8"
        )

        guarded = "\n".join(guarded_regions(src, "SNIFFER_TX_CAPABLE"))
        self.assertIn("transmit", guarded, "the guarded region should hold the transmit call")

        for receive_only in ("::begin(", "::poll(", "::readEvidence(", "::configure(", "::stop("):
            self.assertNotIn(
                receive_only,
                guarded,
                f"{receive_only} is receive-side and must not be compiled out by a TX flag",
            )

        # And the modem handle itself has to exist unconditionally, or the receive paths
        # above compile to nothing.
        self.assertIn("static SX1262* g_modem = nullptr;", src)
        self.assertIn("#include <RadioLib.h>", src)

    def test_the_firmware_mounts_the_filesystem_its_slot_declares(self):
        # `fs_sniffer` is declared `spiffs` in both shipped tables. Mounting LittleFS on
        # it mounted nothing, so every boot silently fell back to the built-in regional
        # default -- an import that silently did nothing.
        main = (ROOT / "firmware" / "src" / "main.cpp").read_text(encoding="utf-8")
        mounted = set(re.findall(r"\b(SPIFFS|LittleFS)\.begin\(", main))
        self.assertEqual(
            len(mounted),
            1,
            f"expected exactly one filesystem mounted, found {sorted(mounted)}",
        )
        fs_type = mounted.pop().lower()

        for table in sorted((ROOT / "firmware" / "partitions").glob("*.csv")):
            rows = [
                line.split(",")
                for line in table.read_text(encoding="utf-8").splitlines()
                if not line.lstrip().startswith("#") and "," in line
            ]
            # ESP-IDF CSV columns: name, type, subtype, offset, size, flags.
            sniffer_fs = [
                r for r in rows if len(r) > 2 and r[0].strip() == "fs_sniffer"
            ]
            self.assertEqual(len(sniffer_fs), 1, f"{table.name} has no single fs_sniffer row")
            self.assertEqual(
                sniffer_fs[0][2].strip().lower(),
                fs_type,
                f"{table.name} declares fs_sniffer as "
                f"{sniffer_fs[0][2].strip()} but main.cpp mounts {fs_type}",
            )

    def test_partition_subtypes_are_keywords_the_bootloader_knows(self):
        # Every partition row needs a *type* and a *subtype*, and ESP-IDF accepts only a
        # fixed list of subtype keywords.
        #
        # The `otadata` partition was generated with subtype `otadata`, which is a fine
        # partition *name* and not a keyword at all. Nothing in the host gate noticed; the
        # error only appeared when a partition table was first compiled for the chip, as
        # "Value 'otadata' is not valid".
        app_subtypes = {"factory", "test", "undefined"} | {f"ota_{i}" for i in range(16)}
        data_subtypes = {
            "ota", "phy", "nvs", "coredump", "nvs_keys", "efuse", "undefined",
            "esphttpd", "fat", "spiffs",
            # ESP-IDF 5.1+, which is what Meshtastic's slot needs. Not in the pinned
            # arduino-esp32 2.x generator -- see docs/SLOTS.md.
            "littlefs",
        }

        for table in sorted((ROOT / "firmware" / "partitions").glob("*.csv")):
            for lineno, line in enumerate(
                table.read_text(encoding="utf-8").splitlines(), 1
            ):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                cols = [c.strip() for c in line.split(",")]
                if len(cols) < 3:
                    continue
                _, ptype, subtype = cols[0], cols[1], cols[2]
                allowed = app_subtypes if ptype == "app" else data_subtypes
                self.assertIn(
                    subtype,
                    allowed,
                    f"{table.name}:{lineno} subtype {subtype!r} is not a valid "
                    f"{ptype} subtype",
                )

    def test_profiles_scale_down_rather_than_guessing(self):
        memory = (ROOT / "firmware" / "include" / "sniffer" / "MemoryBudget.hpp").read_text(
            encoding="utf-8"
        )
        for profile in ("kProfileBare", "kProfileStandard", "kProfilePsram"):
            self.assertIn(profile, memory)
        # Capacities must actually differ between profiles, or scaling is cosmetic.
        caps = re.findall(r"kProfile\w+ = \{[^}]*?,\s*\d+,\s*(\d+)\}", memory)
        self.assertGreaterEqual(len(set(caps)), 2, "every profile has the same device capacity")


if __name__ == "__main__":
    unittest.main(verbosity=2)
