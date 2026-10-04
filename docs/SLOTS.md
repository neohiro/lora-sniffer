# Slots, and standing in for the mesh

## What this is

The sniffer is a **slot tool**, alongside MeshCore and Meshtastic, in the same layout
[meshcore-meshtastic-heltec-v4](https://github.com/neohiro/meshcore-meshtastic-heltec-v4)
established. Nothing about that geometry is changed here.

```
# not rows: 0x00000  bootloader, flashed out of band
# not rows: 0x08000  the partition table itself, one 4 KB sector
otadata        0x14000
nvs            0x16000
coredump       0x20000   below the slots, so capacity is one subtraction

ota_0  0x30000   fs_meshcore     MeshCore      repeater or companion
ota_1  0x330000  fs_meshtastic   Meshtastic    stock firmware, mounts LittleFS
ota_2  0x630000  fs_sniffer      Sniffer       this firmware
ota_3  0x930000  fs_reticulum    reserved
ota_4  0xC30000  fs_lorawan      reserved
```

The first two are marked because they are **not rows in the CSV**. The bootloader is
flashed at `0x0` by convention and the partition table occupies the 4 KB sector at
`0x8000` whether or not the file mentions it. Listing the table as a row is fatal rather
than redundant — see [Building these tables](#building-these-tables-littlefs-and-the-platform-version).

Each slot is a 2 MB app followed by a 1 MB filesystem, on a fixed 3 MB stride.

## The four properties that make this safe

Inherited from the bridge, restated because they are what the sniffer relies on:

1. **Append-only.** Slot *n*'s address is arithmetic in *n*, so the five-slot table
   contains the two-slot table verbatim. No code path can relocate a partition already
   holding firmware, and `tests/test_partition_csv.cpp` checks it against the shipped
   files rather than asserting it in a comment.

2. **Fixed below the slots.** The bootloader, partition table, otadata, NVS and coredump
   never move, which is what makes capacity a subtraction rather than a moving target.

3. **Transport-independent.** USB, BLE and WiFi are labels on the same service. The
   sniffer adds one `CaptureSink` and nothing else.

4. **64 KB app alignment.** An app partition that is not aligned is refused by the
   bootloader *with no log at all*, so a board with one simply looks dead.

## Two decisions the sniffer makes explicitly

**Its own filesystem.** Not shared with MeshCore, and not "the MeshCore slot with a
flag". A sniffer booted into somebody's repeater slot would need to keep its own
settings somewhere, and the only places available are the other side's — which is how a
repeater's channel keys get reformatted by a tool an operator ran for five minutes.
`validateForSniffer()` refuses any table where two slots share a filesystem label, and
`tools/flash.py` refuses the same thing before writing anything.

**Third, not first.** The first slot is what a virgin board comes up as, and the
firmware that should be first into a board is the one that *runs the mesh*. A board that
has been sitting in a box should come up as a working MeshCore node, not as a logger
somebody forgot to turn off. The sniffer is offered when it is wanted, which is after
the mesh is already running. The refusal explains this rather than just stating the
fact:

```
the sniffer lives in slot 3 and this layout has 2. MeshCore first, then Meshtastic,
then the sniffer -- it is offered third on purpose, because the first slot is what a
virgin board comes up as, and that should be a working mesh node rather than a logger
somebody forgot to turn off
```

## "Alongside", precisely

At most one slot executes. The sniffer and the repeater **never run at the same time on
one board**, and this project does not pretend otherwise.

What it does instead is the operationally useful version:

1. The repeater runs in slot 0 and writes its settings into `fs_meshcore`.
2. You flash the sniffer into **slot 2**, leaving slot 0 and its filesystem untouched.
3. You boot the sniffer. It reads the settings already in its own slot — or, in the
   shipped `triboot` layout, in the slot it was provisioned with — and **listens where
   the repeater was listening**.
4. You `filter untraceable=true`, or `devices`, or `stats`.
5. You boot back into the repeater. Its settings are exactly as they were, because the
   sniffer never wrote to them.

Step 3 is `RfPlanSource`, and it is the reason the sniffer is useful rather than
decorative:

```
[fs] read 412 bytes of settings from this slot
[plan] 869.525MHz 250kHz SF11 4/5 explicit crc (from imported settings)
[plan] frequency imported from this slot's settings
```

The parsing is `#define`-based, and that is a property of the format rather than a
convenience: MeshCore firmware persists its settings as a C header of `#define`s and
includes it, so a `#define` scanner reads exactly the values the firmware itself compiles
with. There is no YAML to parse on a microcontroller and no protobuf schema to vendor.

Precedence, and the origin is printed every time so "why is it hearing nothing" has a
one-line answer:

| Order | Source | Why |
|---|---|---|
| 1 | command-line override | the operator who typed a frequency meant it |
| 2 | build flags | a deliberate build-time choice |
| 3 | **the slot's own settings** | this is the repeater's configuration, and it should win over nothing |
| 4 | region default | the fallback |

A settings import that differs from the community default is stated, not treated as an
error — a sniffer exists precisely to look at plans that are not the default:

```
this plan is not the community default, so nothing on the default plan will be heard
```

## Flashing

Two tables ship here:

| Table | Slots | For |
|---|---|---|
| `triboot.csv` | 5 | the shared layout, sniffer as slot 2. **This is the one you want.** |
| `snifferboot.csv` | 1 | the sniffer alone, for a board with nothing else on it |

Both are generated by `tools/gen_layouts.py` from `SlotPlan.hpp`, and
`tests/test_repo_hygiene.py` regenerates and compares them — so a geometry change cannot
quietly desynchronise the committed tables.

```bash
python tools/flash.py --table triboot \
  --bootloader  firmware/.pio/build/heltec_v4_sniffer_standalone/bootloader.bin \
  --part-table-bin firmware/.pio/build/heltec_v4_sniffer_standalone/partitions.bin \
  --app sniffer=firmware/.pio/build/heltec_v4_sniffer_standalone/firmware.bin --dry-run
```

`--app` takes either a framework name or a partition label. `sniffer` resolves through
`SlotPlan.hpp`'s own role table, so it picks slot 2 for `triboot` and slot 0 for
`snifferboot` without this document having to repeat the layout; `ota_2` also works if
you are reading the CSV.

`--dry-run` validates and prints the write plan and writes nothing. Use it first; the
refusals are the interesting part.

The bootloader and the partition table are written to the fixed addresses `0x0000` and
`0x8000`. They are constants in `tools/flash.py`, not lookups against the table, because
the table must not contain them.

## Adding the sniffer to the bridge's table

The bridge repo owns its own partition CSVs. To add the sniffer there:

1. Add `ota_2 / fs_sniffer` at the slot-2 address the geometry computes
   (`0x630000`, app `0x200000`, fs `0x830000` on a 16 MB board with a 5-slot table).
2. Give it `spiffs`, like MeshCore. Meshtastic's `littlefs` and MeshCore's `spiffs` are
   not interchangeable — see the pairing rule below.
3. Renumber `ota_3`/`ota_4` only if the bridge's own geometry changes. Do not renumber
   `ota_0` or `ota_1`: their addresses are already arithmetic and every existing board
   depends on them.

The pairing rule is the mistake worth being careful about, and it is checked in four
places — `SlotPlan::validateForSniffer()`, `tools/flash.py::validate()`,
`tests/test_partition_csv.cpp` and `tests/test_repo_hygiene.py`:

> Meshtastic mounts **LittleFS** and MeshCore mounts **SPIFFS**. Handing either side
> the other's filesystem type makes it format the wrong one on boot and lose the
> settings of the other side of the pair, with no error anywhere.

### One row differs from lora-multiboot

[`neohiro/lora-multiboot`](https://github.com/neohiro/lora-multiboot) uses the same
geometry — same first slot, same stride, same app and filesystem sizes — but declares
`fs_meshtastic` as **`spiffs`** where this table declares **`littlefs`**.

That is the whole of the disagreement, and it is not cosmetic in either direction:

- Taking **this** table for a multiboot board hands Meshtastic a `littlefs` partition it
  does not mount there.
- Taking **multiboot's** table for a bridge-project board hands Meshtastic a `spiffs`
  partition where the older firmware expects LittleFS.

Whichever pair of projects you are running, take one project's table and add the sniffer
slot to it. Do not mix rows from both. And whichever you take, the rule above still
holds: the sniffer's filesystem is its own and is never shared with a mesh stack.

## Building these tables: `littlefs` and the platform version

`triboot.csv` gives Meshtastic's slot the `littlefs` subtype, which is what that
firmware mounts and what the reference `quadboot.csv` uses. It is also the one row the
pinned PlatformIO platform cannot build:

```
Value 'littlefs' is not valid. Known keywords: ota, phy, nvs, coredump, nvs_keys,
efuse, undefined, esphttpd, fat, spiffs
```

`espressif32@^6.9.0` ships arduino-esp32 2.x, whose partition generator predates the
`littlefs` subtype; it arrived in ESP-IDF 5.1. So:

| Env | Table | Builds on `espressif32@^6.9.0`? |
|---|---|---|
| `heltec_v4_sniffer` | `triboot.csv` | no — `littlefs` |
| `heltec_v4_sniffer_beacon` | `triboot.csv` | no — `littlefs` |
| `heltec_v4_sniffer_standalone` | `snifferboot.csv` | **yes** |
| `heltec_v4_sniffer_beacon_standalone` | `snifferboot.csv` | **yes** |

The two standalone envs exist partly so CI can compile the firmware at all on the pinned
platform, including the transmit path. The shared table is flashed rather than
rebuilt-by-the-operator in the normal workflow, and building it needs a newer core
(arduino-esp32 3.x or ESP-IDF 5.1+).

Do **not** "fix" the build error by changing `littlefs` to `spiffs`. That would satisfy
the generator by handing Meshtastic a filesystem it does not mount, which is exactly the
silent settings loss the pairing rule above exists to prevent.

Two more things the chip checks that no host test can, both of which were wrong here
before they were compiled:

- The bootloader and the partition table are **not rows**. The table lives in the 4 KB
  sector at `0x8000` whether or not a row says so, and listing it produces `first
  partition offset 0x0 overlaps end of partition table 0x9000`.
- Every row's *subtype* must be a keyword from the list above. `otadata` is a valid
  partition **name** and an invalid subtype.

## Memory, per slot

The sniffer's tables scale with a compile-time profile, and the boot check measures the
board rather than assuming:

| Profile | Devices | Ring lines | Working set |
|---|---:|---:|---|
| `psram` | 256 | 256 | 116.5 KiB |
| `standard` | 64 | 48 | 32.0 KiB |
| `bare` | 32 | 16 | 18.7 KiB |

```
[boot] fit         ok
[boot] profile     256 devices, 256 ring lines
[boot] working set 116KB of 168KB free heap
```

A five-slot table on an 8 MB board is refused twice: by `flash.py`, before anything is
written, and again by `MemoryBudget::checkFit()` at boot, because a running firmware
should be able to say what it was flashed as and refuse to proceed.

See [MEMORY.md](MEMORY.md).
