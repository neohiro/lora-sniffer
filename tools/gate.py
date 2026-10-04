#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The gate.

Compiles the portable firmware logic with the same strict flags CI uses, runs its
suites against the shipped partition tables, then runs the host tooling's own
tests.

Why a Python driver rather than a bare `make`: the compiler is the only thing this
needs, and a C++ compiler is the one dependency we cannot avoid. `make` is
avoidable, and GitHub's Windows and macOS images do not guarantee it, so a
Makefile-only gate fails on the runner for a reason that has nothing to do with the
code. The Makefile still exists and still works; it delegates here.

    python tools/gate.py
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Mirrors CXXFLAGS in the Makefile. -Werror is the point: a warning that would
# once have been a note fails the build instead of quietly accumulating.
STRICT_GCC = [
    "-std=c++17",
    "-O1",
    "-g",
    "-Wall",
    "-Wextra",
    "-Wpedantic",
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-Werror",
]

FIRMWARE_SRC = [
    "firmware/src/Protocol.cpp",
    "firmware/src/RfPlan.cpp",
    "firmware/src/Provenance.cpp",
    "firmware/src/PlanRegistry.cpp",
    "firmware/src/Classifier.cpp",
    "firmware/src/MeshCoreFrame.cpp",
    "firmware/src/MeshCorePayload.cpp",
    "firmware/src/MeshtasticFrame.cpp",
    "firmware/src/LoRaWanFrame.cpp",
    "firmware/src/Fingerprint.cpp",
    "firmware/src/Record.cpp",
    "firmware/src/Filter.cpp",
    "firmware/src/Counters.cpp",
    "firmware/src/Jsonl.cpp",
    "firmware/src/Wire.cpp",
    "firmware/src/Capture.cpp",
    "firmware/src/DeviceTable.cpp",
    "firmware/src/MemoryBudget.cpp",
    "firmware/src/Beacon.cpp",
    "firmware/src/CommandLine.cpp",
    "firmware/src/TxLockout.cpp",
    "firmware/src/SlotPlan.cpp",
    "firmware/src/RfPlanSource.cpp",
]

TEST_SRC = [
    "tests/main.cpp",
    "tests/test_rf_plan.cpp",
    "tests/test_protocol.cpp",
    "tests/test_classifier.cpp",
    "tests/test_meshcore.cpp",
    "tests/test_meshtastic_lorawan.cpp",
    "tests/test_capture_format.cpp",
    "tests/test_filter.cpp",
    "tests/test_device_table.cpp",
    "tests/test_pipeline.cpp",
    "tests/test_beacon.cpp",
    "tests/test_partition_csv.cpp",
]

# MSVC has no -W flags and no notion of -Wconversion, so it gets its own set.
STRICT_MSVC = ["/std:c++17", "/W4", "/WX", "/permissive-", "/EHsc", "/Zi", "/Od"]

PY_TESTS = [
    "tests/test_sniffctl.py",
    "tests/test_flash_tool.py",
    "tests/test_repo_hygiene.py",
]


class GateError(RuntimeError):
    pass


def find_compiler(explicit: str | None) -> tuple[str, list[str]]:
    """Return (compiler, base_flags). Prefers whatever the caller named."""
    if explicit:
        for cand in (explicit, f"{explicit}.exe"):
            found = shutil.which(cand)
            if found:
                if "cl" in Path(found).name.lower():
                    return found, STRICT_MSVC
                return found, STRICT_GCC
        # An absolute path that `which` will not resolve (a bare path with no
        # directory entry, for instance) is still worth trying directly.
        if Path(explicit).is_file():
            return explicit, STRICT_MSVC if "cl" in Path(explicit).name.lower() else STRICT_GCC
        raise GateError(f"compiler not found: {explicit}")

    # MSVC first when this is a Visual Studio developer shell.
    if os.environ.get("VSCMD_ARG_TGT_ARCH"):
        cl = shutil.which("cl")
        if cl:
            return cl, STRICT_MSVC

    for cand in ("g++", "clang++", "c++"):
        found = shutil.which(cand)
        if found:
            return found, STRICT_GCC
    return "cl", STRICT_MSVC


def compile_and_run(verbose: bool) -> int:
    cxx, base = find_compiler(os.environ.get("CXX"))
    is_msvc = "cl" in Path(cxx).name.lower()

    out_dir = ROOT / "build"
    out_dir.mkdir(exist_ok=True)
    binary = out_dir / ("sniffer-tests.exe" if platform.system() == "Windows" else "sniffer-tests")

    includes = [f"-I{ROOT / 'firmware' / 'include'}", f"-I{ROOT / 'tests'}"]
    if is_msvc:
        includes = [f"/I{ROOT / 'firmware' / 'include'}", f"/I{ROOT / 'tests'}"]

    cmd = [cxx, *base, *includes]
    # The output has to be named explicitly. Appending the binary path with no -o
    # makes the driver treat it as an object to link, which fails with a baffling
    # "cannot find <the file we just asked it to create>".
    cmd += ["/Fe:" + str(binary)] if is_msvc else ["-o", str(binary)]
    cmd += [str(ROOT / s) for s in FIRMWARE_SRC + TEST_SRC]

    print(f"compiler: {cxx}")
    print("flags:    " + " ".join(base))
    print()

    proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise GateError("compilation failed")
    if proc.stderr.strip():
        # With -Werror there should be nothing here, but say so rather than
        # discarding it if a compiler disagrees about a warning.
        sys.stderr.write(proc.stderr)
    if verbose and proc.stdout.strip():
        sys.stdout.write(proc.stdout)

    run = subprocess.run(
        [str(binary), str(ROOT / "firmware" / "partitions")],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)
    return run.returncode


def run_python_tests(verbose: bool) -> int:
    """Run each host-tooling test file and report which ones failed.

    unittest writes its results to **stderr**, not stdout, so only capturing stdout
    prints nothing at all for a passing file and hides the failure detail for a
    failing one. Both streams are captured and both are shown.

    The tail of the failure output is printed even on success when verbose, because
    "0 tests ran" and "11 tests ran" look identical otherwise and a test file that
    silently stopped collecting is indistinguishable from a file that passes.
    """
    failures: list[str] = []
    for rel in PY_TESTS:
        print()
        print(f"== {Path(rel).name} ==")
        proc = subprocess.run(
            [sys.executable, rel],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        combined = (proc.stdout + proc.stderr).strip()

        if proc.returncode != 0:
            failures.append(Path(rel).name)
            print(combined)
        elif verbose and combined:
            print(combined)
        else:
            # The last line unittest prints is the count, which is the part worth
            # seeing without -v.
            tail = [ln for ln in combined.splitlines() if ln.strip()]
            for ln in tail[-2:]:
                print(ln)

    if failures:
        print()
        print("failing: " + ", ".join(failures))
    return len(failures)


def check_tx_gate(verbose: bool) -> int:
    """The RX-only guarantee, enforced on the source rather than asserted in a README.

    Every transmit call site in the radio layer has to go through the beacon build
    guard. A grep is a crude tool, but it is the only check that catches a new
    `radio.transmit(...)` before it ships in the default image, and a sniff that can
    key up is the one defect this repository must not have.
    """
    print()
    print("== transmit gate ==")

    offenders: list[str] = []
    pattern = re.compile(r"\.\s*(transmit|sendPacket|startTransmit|setDioIrqParamsAsTransmit)")
    for path in sorted(ROOT.rglob("*.cpp")):
        if "build" in path.parts or ".pio" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "kBeaconBuild" not in text and "SNIFFER_TX_CAPABLE" not in text:
            # A file with no guard at all cannot contain a permitted call site.
            for lineno, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("//"):
                    continue
                if pattern.search(line):
                    rel = path.relative_to(ROOT)
                    offenders.append(f"{rel}:{lineno}: {line.strip()}")
            continue

        # Inside a guarded file, a call is only acceptable within an `#if` block that
        # mentions the guard. Tracked as a running flag rather than a lookahead so
        # the check stays a line-by-line loop.
        guarded = False
        depth_guard = 0
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#if"):
                if "kBeaconBuild" in line or "SNIFFER_TX_CAPABLE" in line:
                    guarded = True
                    depth_guard = 1
            elif guarded and stripped.startswith("#endif") and depth_guard > 0:
                depth_guard -= 1
                if depth_guard == 0:
                    guarded = False
            elif guarded and stripped.startswith("#if"):
                depth_guard += 1

            if guarded or stripped.startswith("//"):
                continue
            if pattern.search(line):
                rel = path.relative_to(ROOT)
                offenders.append(f"{rel}:{lineno}: {stripped}")

    if offenders:
        for line in offenders:
            print(f"  unguarded transmit call: {line}")
        print(
            "\n  a transmit call outside the beacon build guard. The default image\n"
            "  must be unable to key up; see firmware/include/sniffer/TxLockout.hpp"
        )
        return 1

    header = (ROOT / "firmware" / "include" / "sniffer" / "TxLockout.hpp").read_text(
        encoding="utf-8"
    )
    if "constexpr bool mayTransmit() { return false; }" not in header:
        print("  TxLockout.hpp no longer states mayTransmit() == false unconditionally")
        return 1

    print("  the default build cannot transmit; the beacon path is behind a build flag")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    try:
        cpp = compile_and_run(args.verbose)
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    py = run_python_tests(args.verbose)
    tx = check_tx_gate(args.verbose)

    print()
    if cpp == 0 and py == 0 and tx == 0:
        print("GATE PASS")
        return 0
    print(
        f"GATE FAIL (firmware logic={cpp}, "
        f"host tooling={py} of {len(PY_TESTS)} failing, transmit gate={tx})"
    )
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except GateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
