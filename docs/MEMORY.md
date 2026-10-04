# Memory

Every fixed table in this firmware is capacity-parameterised so its size is a
compile-time `sizeof`, and the boot check **measures the board** rather than trusting a
datasheet. This document is why, and what the numbers are.

## The constraint

The sniffer is one guest on a board that belongs to somebody else's mesh. The same
Heltec V4 runs MeshCore, Meshtastic and this firmware out of five slots, and every one
of those images expects to have the machine to itself when it boots. So:

- **The flash size is read from the chip**, never assumed. A five-slot table on an 8 MB
  board overruns, and the bootloader will not say so. Refused twice: by `flash.py`
  before anything is written, and again by `checkFit()` at boot.
- **The heap is measured after everything else has taken its share.** `freeHeap()` at
  boot reflects what WiFi, BLE and the filesystem mount have already used. A datasheet
  figure would be a lie.
- **The requirement scales down.** On a board with no PSRAM the device table shrinks and
  the ring shrinks, rather than the firmware carrying a fixed size and fragmenting.

## The profiles

| Profile | Devices | Ring lines | Working set | For |
|---|---:|---:|---:|---|
| `bare` | 32 | 16 | 18.7 KiB | no PSRAM, 4 MB flash |
| `standard` | 64 | 48 | 32.0 KiB | 8 MB flash, no PSRAM |
| `psram` | 256 | 256 | 116.5 KiB | a Heltec V4 with PSRAM |

A profile is a **floor for a board class**, not a spec for a board. It carries the
capacities the tables are sized for, and `checkFit()` compares them against the heap the
board actually reports.

Selecting a PSRAM profile on a board with none is refused rather than accepted:

```
the 'psram' profile expects 8192KB of PSRAM and none was found. Falling back is the
operator's call, not this firmware's: the capacities below assume it
```

Running at twice the intended capacity would present as fragmentation hours later, not
at boot. That is the failure this check exists to prevent.

## What the working set is

`workingSetBytes()` is a sum of real `sizeof`s:

| Term | Bytes |
|---|---|
| `CaptureEngine` (holds the record, the counters, the filter, the fingerprint table) | 4240 |
| one `Record` | 1928 |
| `Counters` | 152 |
| `FilterSpec` | 88 |
| `PlanVerdict` | 176 |
| `RfParams` | 16 |
| `LinkEvidence` | 12 |
| `DeviceTable<N>` | `N × sizeof(Device) + 8` |
| capture ring | `ringLines × 320` |
| one JSON line buffer | 2048 |
| one wire frame buffer | 2048 |

Those are the actual `sizeof`s on a desktop compiler, not estimates, and they sum to
119,260 bytes for the PSRAM profile. If a term is ever missing from this table the
number here stops matching `workingSetBytes()`, which is the point of writing it down.

There is no constant anywhere to forget. Adding a table changes the number the boot check
uses at compile time, and `tests/test_repo_hygiene.py` checks that every profile's
capacities actually differ — so scaling cannot become cosmetic.

The ring holds **formatted lines, not `Record`s**. A `Record` is 1.9 KB and a JSON line
is a few hundred bytes; holding a hundred of those on a board with no PSRAM is the
difference between working and thrashing.

## What it prints

```
[boot] fit         ok
[boot] profile     256 devices, 256 ring lines
[boot] working set 116KB of 168KB free heap
[boot] with margin 137KB
[boot] app         400KB used of 2048KB slot
[boot] slots       5 declared, 5 fit this flash
[boot] psram       7860KB free
```

Every line is a decision an operator can act on. The profile line is there because the
profile *decides* the capacities, so it belongs next to them.

The two KB figures are the ones that matter and they are both measured rather than
illustrative: 116 KB is `workingSetBytes(256, 256)`, and 137 KB is that plus an eighth of
the free heap. An earlier version of this document showed 176 KB of working set against
168 KB of free heap and a verdict of `ok`, which the code cannot produce — `checkFit()`
returns `heap-too-small` when the working set exceeds free heap. A sample log that
contradicts the function it illustrates is worse than no sample.

The `app` figure is 400 KB because that is what the image actually measures: a real
`heltec_v4_sniffer_standalone` build links at 409,873 bytes against a 2,097,152-byte
slot.

## Headroom, and what "too small" means

`workingSetBytes()` is what the tables occupy. Headroom is an eighth of free heap on
top, because the firmware also prints, mounts a filesystem and formats JSON lines — none
of which is in a `sizeof`. A tenth of free heap is not much to give away when the
alternative is a device that works on the bench and fragments itself on a roof.

Three verdicts, and they are deliberately different:

| Verdict | Meaning |
|---|---|
| `heap-too-small` (below the working set) | refuse; try a smaller profile |
| `heap-too-small` (below working set + headroom) | **warn and carry on** — "expect gaps in the capture if something else claims memory later" |
| `ok` | proceed |

Warning rather than refusing in the middle case is a judgement: the capture is the
product, and a sniffer that refuses to start because WiFi took 20 KB more than expected
is less useful than one that starts and says what it expects to lose.

## The radio does not allocate either

`Sx1262Promiscuous::poll()` writes into a caller-provided frame and copies at most 255
bytes into a stack buffer. `Console::observe()` renders into a fixed 2 KB buffer and the
ring copies into its own. The only heap use on the capture path is `std::string` inside
the portable renderers, which are called once per frame rather than once per field.

This is why the strict flag set includes `-Wconversion` and `-Wsign-conversion`: a radio
struct hands you a `size_t` where the protocol wants a `uint16_t`, and every narrowing
in the capture path is a place a length field could be truncated into something that
looks like a valid frame.

## Building for a smaller board

```bash
pio run -d firmware -e heltec_v4_sniffer_standalone \
  --project-option="build_flags=-DSNIFFER_PROFILE_PSRAM=0"
```

which selects the `standard` profile at compile time, halving the device table and the
ring. The boot check still verifies the result against what the board reports, so a
mismatched guess is caught rather than discovered on a roof.

## Checklist for a new fixed table

1. Is it capacity-parameterised? If not, `sizeof` is a constant and the check drifts.
2. Is it zero-initialised, and does the type have a trivial destructor? A table of
   non-trivial objects costs the firmware constructors it never needs.
3. Does it have a `static_assert` guarding the capacity formula against a real instance?
   `deviceTableBytes()` and `DeviceTable<N>` are cross-checked exactly this way.
4. Does a full table still behave? Overflow must evict, not refuse — a sniffer that
   stopped counting after 64 distinct frames is worse than one that forgets the oldest.
