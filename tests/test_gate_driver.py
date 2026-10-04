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
    """The flag sets themselves.

    These call `flags_for_kind` with an explicit kind, never `flags_for("g++")`. That is
    not a style preference: on macOS `g++` is a Clang, so a test that says "g++ gets
    GCC's flags" is really asserting something about the machine it runs on. Such a test
    passes on Linux and fails on the one platform whose behaviour it claims to describe,
    which is exactly how the original bug survived a green build here.
    """

    def test_gcc_gets_level_two(self):
        flags = gate.flags_for_kind(gate.KIND_GCC)
        self.assertIn(LEVEL2, flags)
        self.assertNotIn(UNLEVILED, flags)

    def test_clang_gets_the_unlevelled_warning(self):
        flags = gate.flags_for_kind(gate.KIND_CLANG)
        self.assertIn(UNLEVILED, flags)
        self.assertNotIn(LEVEL2, flags)

    def test_msvc_gets_no_dash_w_flags_at_all(self):
        flags = gate.flags_for_kind(gate.KIND_MSVC)
        self.assertTrue(flags, "MSVC needs its own set, not an empty one")
        for flag in flags:
            self.assertFalse(flag.startswith("-W"), flag)

    def test_the_truncation_flags_are_mutually_exclusive(self):
        """The defect, stated as a property.

        GCC and Clang disagree about how this warning is spelled, and passing the wrong
        spelling is a hard error under -Werror rather than a warning nobody reads. So no
        two kinds may share the option.
        """
        kinds = (gate.KIND_GCC, gate.KIND_CLANG, gate.KIND_MSVC)
        for kind in kinds:
            flags = gate.flags_for_kind(kind)
            if kind != gate.KIND_GCC:
                self.assertNotIn(LEVEL2, flags, kind)
            if kind != gate.KIND_CLANG:
                self.assertNotIn(UNLEVILED, flags, kind)

    def test_every_set_keeps_the_strict_baseline(self):
        """Whatever else changes, -Werror and the conversion warnings stay."""
        for kind in (gate.KIND_GCC, gate.KIND_CLANG, gate.KIND_MSVC):
            flags = gate.flags_for_kind(kind)
            if kind == gate.KIND_MSVC:
                self.assertIn("/WX", flags, kind)  # MSVC's -Werror
            else:
                self.assertIn("-Werror", flags, kind)
                self.assertIn("-Wconversion", flags, kind)
                self.assertIn("-Wsign-conversion", flags, kind)

    def test_an_unknown_kind_falls_back_to_gcc(self):
        # A new compiler should get the strictest set rather than an empty one.
        self.assertIn(LEVEL2, gate.flags_for_kind("something-new"))


class CompilerIdentification(unittest.TestCase):
    """Name first, then the compiler's own answer.

    Only the unambiguous names are asserted here. What `g++` resolves to is a property of
    the machine, which is the whole reason `looks_like_clang` exists.
    """

    def test_names_that_are_unambiguous(self):
        cases = {
            "clang++": gate.KIND_CLANG,
            "clang": gate.KIND_CLANG,
            "clang++.exe": gate.KIND_CLANG,
            "C:/VS/bin/cl.exe": gate.KIND_MSVC,
            "clang-tidy": gate.KIND_CLANG,
        }
        for name, want in cases.items():
            self.assertEqual(gate.compiler_kind(name), want, name)

    def test_clang_is_not_mistaken_for_msvc(self):
        # "cl" is a substring of "clang". Getting this backwards sends every Clang build
        # to the MSVC flag set, which fails immediately and obviously -- but only after
        # the interesting mistake has been made.
        self.assertEqual(gate.compiler_kind("clang++"), gate.KIND_CLANG)


if __name__ == "__main__":
    unittest.main(verbosity=2)
