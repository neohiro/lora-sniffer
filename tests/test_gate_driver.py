#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for tools/gate.py itself.

The gate is the definition of passing for this repository, so it is the one piece of
tooling that was going untested while everything it checks was tested hard.

Two defects here were found by CI rather than by a test, and both are of the same shape:
the gate handed a compiler a flag that compiler does not accept, and the build failed
before compiling anything.

    # Every compiler got GCC's level 2. Clang has no level 2.
    # `g++` was matched by name, so macOS -- where `g++` *is* Clang -- got it too.

The second is the one worth a test. "Ask the compiler instead of guessing from its name"
is only true if the asking is correct, and on this developer's machine a stand-in for a
Clang-named g++ cannot even be executed, so the assertion has to be made against the
version strings rather than against a subprocess.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import gate  # noqa: E402

LEVEL2 = "-Wformat-truncation=2"
UNLEVILED = "-Wformat-truncation"


class ClangDetection(unittest.TestCase):
    """`looks_like_clang` is the decision; `is_clang` is one subprocess around it."""

    def test_recognises_clang_from_real_version_strings(self):
        # What each platform actually prints for a C++ compiler.
        cases = [
            "Apple clang version 17.0.0 (clang-1700.3.9.1)",
            "Ubuntu clang version 18.1.3 (++202401121)",
            "clang version 20.1.0 (https://github.com/llvm/llvm-project ...)",
            "Debian clang version 14.0.6",
        ]
        for text in cases:
            self.assertTrue(gate.looks_like_clang(text), text)

    def test_real_gcc_is_not_mistaken_for_clang(self):
        cases = [
            "g++ (GCC) 13.2.0",
            "g++ (Rev3, Build by GNU) 12.2.0",
            "x86_64-w64-mingw32-g++ (GCC) 13.2.0",
            "gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0",
        ]
        for text in cases:
            self.assertFalse(gate.looks_like_clang(text), text)

    def test_empty_output_is_not_clang(self):
        # A compiler that will not answer is not evidence of anything. Guessing Clang
        # there would disable the GCC-only warnings on a broken toolchain.
        self.assertFalse(gate.looks_like_clang(""))
        self.assertFalse(gate.looks_like_clang("   \n"))


class FlagSelection(unittest.TestCase):
    def test_gcc_gets_level_two(self):
        self.assertIn(LEVEL2, gate.flags_for("g++"))
        self.assertIn(LEVEL2, gate.flags_for("x86_64-w64-mingw32-g++"))

    def test_clang_gets_the_unlevelled_warning(self):
        for name in ("clang++", "clang", "clang++.exe"):
            flags = gate.flags_for(name)
            self.assertIn(UNLEVILED, flags, name)
            self.assertNotIn(LEVEL2, flags, name)

    def test_msvc_gets_no_dash_w_flags_at_all(self):
        flags = gate.flags_for("cl")
        self.assertTrue(flags, "MSVC needs its own set, not an empty one")
        for flag in flags:
            self.assertFalse(flag.startswith("-W"), flag)

    def test_the_truncation_flags_are_mutually_exclusive(self):
        """The defect, stated as a property.

        GCC and Clang disagree about how this warning is spelled, and passing the wrong
        spelling is a hard error under -Werror rather than a warning nobody reads. So the
        two sets must not share the option: whichever one a compiler gets, the other must
        not.
        """
        gcc_flags = gate.flags_for("g++")
        clang_flags = gate.flags_for("clang++")
        self.assertNotIn(LEVEL2, clang_flags)
        self.assertNotIn(UNLEVILED, gcc_flags)

    def test_every_set_keeps_the_strict_baseline(self):
        """Whatever else changes, -Werror and the conversion warnings stay."""
        for name in ("g++", "clang++", "cl"):
            flags = gate.flags_for(name)
            if name == "cl":
                self.assertIn("/WX", flags, name)  # MSVC's -Werror
            else:
                self.assertIn("-Werror", flags, name)
                self.assertIn("-Wconversion", flags, name)
                self.assertIn("-Wsign-conversion", flags, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
