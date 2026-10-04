# Convenience only. The gate itself lives in tools/gate.py.
#
# `make check` and `python tools/gate.py` run identical checks. The Python driver
# exists because a C++ compiler is the one dependency we cannot avoid, while
# `make` is avoidable -- and GitHub's Windows and macOS images do not guarantee
# it, so a Makefile-only gate fails on the runner for reasons that have nothing
# to do with the code.

CXX      ?= g++
# -Wformat-truncation=2 rather than the level -Wall implies: level 1 proved none of
# ours, and three error strings longer than their buffers passed every Linux and Windows
# build. Level 2 fails on the machine that is pushing.
CXXFLAGS ?= -std=c++17 -O1 -g -Wall -Wextra -Wpedantic -Wshadow \
            -Wconversion -Wsign-conversion -Wformat-truncation=2 -Werror
PYTHON   ?= python3

.PHONY: all check layouts clean

all: check

## check: the whole gate
check:
	$(PYTHON) tools/gate.py

## layouts: regenerate the shipped partition tables from the code's geometry
layouts:
	$(PYTHON) tools/gen_layouts.py

clean:
	rm -rf build
