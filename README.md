<h1 align="center">lora-sniffer</h1>

<p align="center">
  A Heltec LoRa 32 V4 that listens to everything on a frequency and tells you
  <b>what each message is</b>, <b>which mesh it belongs to</b>, and
  <b>which ones nothing can explain</b>.
</p>

<p align="center">
  <a href="https://github.com/neohiro/lora-sniffer/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/neohiro/lora-sniffer/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue.svg">
  <img alt="Board" src="https://img.shields.io/badge/board-Heltec%20LoRa%2032%20V4-16MB%20flash-orange">
</p>

---

> [!IMPORTANT]
> **The sniffer logic is written and tested. The radio is not yet verified against
> hardware.** Everything that decides what a frame means — classification, decoding,
> attribution, filtering, the device list, the capture format — is compiled and
> exercised on a laptop by `python tools/gate.py`, and the whole firmware including the
> radio layer compiles and links for the chip in CI. The SX1262 driver is the untested
> edge, and **two** things it depends on are still open:
>
> 1. **In packet mode the SX1262 strips the sync word.** Whether promiscuous capture
>    delivers the preamble byte to the host depends on the RadioLib path in use. Until
>    that is answered on hardware, the sniffer's *network* attribution degrades honestly
>    to carrier-only, visibly, in the capture stream and in `sniffctl.py --stats`. It does
>    not substitute the configured value, because that would report every frame on the
>    band as MeshCore.
> 2. **The pin map is unverified.** `CS 7, IRQ 13, RST 12, BUSY 14` is the Heltec WiFi
>    LoRa 32 wiring, taken from the board family rather than from the V4 schematic. Check
>    it before putting this on a roof; a wrong BUSY pin is a modem that never completes a
>    transaction.
>
> [Status](#status) · [RF-PLAN.md](docs/RF-PLAN.md)

## What it actually shows you

```
       9 MC MeshCore EU868        x14 4b2e1f0a  -103dBm  grp_txt
    1042 MC MeshCore EU868        x3  91ac33de  -110dBm  advert
    1051 MT Meshtastic EU868 L-f  x6  2c8e0b17   -98dBm  from=!1a2b3c4d
    1063 MT Meshtastic EU868 L-f  x1  ff0091aa  -101dBm  carrier-only
    1074 ?? unlisted network      x5  a1b2c3d4  -100dBm  why sync word 0x99 ...
    1075 ?? ambiguous carrier     x1  77112233  -118dBm  carrier-only
```

```
$ sniffctl --stats capture.jsonl

attribution
  attributed                1,204    86%
  partial                     112     8%
  unattributed                184     6%

  untraceable ratio      6%   (184 of 1,500 analysed frames)

reasons
  fully-decoded           1,204    80%  a registered decoder parsed this and produced...
  encrypted-no-key          112     7%  header read; payload is ciphertext and no ke...
  foreign-sync-word         149    10%  a sync word no registry row has: most likely ...
  known-sync-unknown-body     35     2%  a sync word we name, but no decoder recognis...
```

The six percent is the point. It is the part of the band this firmware could put a name
to, and it is stated as a ratio rather than as two counts because `380 of 400` and
`400 frames, 20 unknown` are not equally legible at 2am on an OLED.

## Three things make it more than a spectrum analyser

**Two meshes share one modulation here.** MeshCore's default and Meshtastic's
`EU_868` LongFast are both 869.525 MHz, 250 kHz, SF11, 4/5 — identical on every field
that decides whether two radios hear each other, and different by **one preamble byte**.
[RF-PLAN.md](docs/RF-PLAN.md)

**Both protocols put something readable in the clear.** MeshCore sends adverts, group
text and control frames unencrypted, so a sniffer with no keys at all can name senders,
roles, locations and channel hashes. Meshtastic's 16-byte header is plaintext whatever
the payload is, so sender, packet id, hop limit and channel hash are always readable.
[WIRE-FORMATS.md](docs/WIRE-FORMATS.md)

**Nothing needs to be guessed.** Every frame carries the name of the decoder that read it
and a reason from a fixed eleven-item taxonomy — so a frame nothing could read is a
classified finding, not a shrug. [ATTRIBUTION.md](docs/ATTRIBUTION.md)

## The unknown-message triage, in three commands

```bash
sniffctl --only-unknown capture.jsonl   # only frames nothing could name
sniffctl --stats capture.jsonl          # where the airtime actually went
sniffctl --unknowns capture.jsonl       # grouped by fingerprint, with the cadence
```

```
7 untraceable frames in 2 distinct shape(s)

!aaaa000000000001  x5  foreign-sync-word  rssi -101..-98 dBm  ~30.0s apart
    net=unlisted network sync=153 carrier=yes len=8
    a sync word 0x99 belongs to no network this firmware has a row for, and the body
    matched nothing. On a shared band this is most likely another community
```

Grouping is what makes this useful. One unattributable frame is a curiosity; forty
byte-identical ones every thirty seconds is a device, and that is the most useful single
thing a sniffer can tell you. The fingerprint covers the raw bytes and the sync word and
deliberately **not** the RSSI or the timestamp — including those would give every repeat
a fresh identity, which is exactly the failure it exists to prevent.

## A separate node list, with two orderings

```
$ sniffctl --devices capture.jsonl

4 nodes, shortest-path order, 1 direct, 2 within 3 hops, 2 with unknown distance
ordered by shortest-path

0  MT deadbeef hops=0  rssi=  -95 name=roof-2    x14 2s ago
1  MT 1a2b3c4d hops=2  rssi= -101 x6  2s ago
2  MC 01020304 hops=?  rssi= -110 role=repeater name=mast-7 x3 1s ago
3  MC 05060708 hops=?  rssi= -112 x1  4s ago
```

Held on the device as its own structure with its own command — not a `grep` over the
log, not a filter — and rebuilt from a capture by `sniffctl` so a file taken on a roof
three days ago can be interrogated tonight.

`shortest-path` first because hop count *is* distance on a flooding mesh.
`--order last-seen` because the default is wrong for a specific moment: a node that
started talking a second ago sorts behind everything heard an hour ago.
[DEVICES.md](docs/DEVICES.md)

Unknown distance sorts **last**, and separately. A frame with no path field is not a
frame from a node next door; putting it first would be the default-looking answer and it
would be a lie.

## A slot tool, not a whole board

```
ota_0  0x30000   fs_meshcore     MeshCore      the repeater or companion
ota_1  0x330000  fs_meshtastic   Meshtastic    stock firmware, mounts LittleFS
ota_2  0x630000  fs_sniffer      Sniffer       this firmware
```

The sniffer is third in the same layout
[meshcore-meshtastic-heltec-v4](https://github.com/neohiro/meshcore-meshtastic-heltec-v4)
uses, with its own filesystem, and it **listens where the repeater it replaced was
listening** — it reads the settings already in its slot at boot:

```
[fs] read 412 bytes of settings from this slot
[plan] 869.525MHz 250kHz SF11 4/5 explicit crc (from imported settings)
```

At most one slot executes, so this is not "alongside" in the simultaneous sense, and the
project does not pretend otherwise. It is the useful version: flash the sniffer into slot
2, look at the band, boot back into the repeater, and its settings are exactly as they
were — because the sniffer never wrote to them. [SLOTS.md](docs/SLOTS.md)

## It cannot transmit

```
[tx] RX-only build: no transmit path is compiled in, so this device cannot key up
```

`mayTransmit()` is `constexpr false` unconditionally, the transmit **call** is compiled
out unless you ask for it, and `tools/gate.py` greps the sources for transmit calls
outside that guard — so a future `radio.transmit(...)` fails CI rather than shipping.

Worth being precise about what the flag does and does not remove, because getting it
backwards is expensive in both directions: the radio, RadioLib and the entire receive
path are compiled into **every** build. Only the transmit call sits behind the flag. An
earlier version of this repository guarded the whole radio file, which meant the default
image — the one everybody flashes — linked no radio at all and captured nothing while
looking, in every other respect, like a working sniffer. `tests/test_repo_hygiene.py`
now fails if the flag ever grows to cover `begin`, `poll`, `configure` or `stop` again.

Sending a message to repeaters is real and is a **separate build**:
[TRANSMIT.md](docs/TRANSMIT.md)

```bash
pio run -d firmware -e heltec_v4_sniffer_beacon_standalone -t upload
# arm, then:
beacon hello there both chan=8F n=5 ms=7000
```

Target-major, so every network gets its first copy before any network gets its second —
a duty-cycle limit that stops the run halfway still covers both meshes. Plaintext only,
because an encoder that takes a key is an encoder that gets a key pasted at it.

## It fits, or it says so

```
[boot] fit         ok
[boot] profile     256 devices, 256 ring lines
[boot] working set 116KB of 168KB free heap
[boot] app         400KB used of 2048KB slot
[boot] slots       5 declared, 5 fit this flash
```

Every fixed table is capacity-parameterised so its size is a compile-time `sizeof`, and
the board is **measured** rather than assumed. Adding a table changes the number the
boot check uses; there is no constant to forget. The profile scales down on a board
without PSRAM rather than the firmware carrying a fixed size and fragmenting.
[MEMORY.md](docs/MEMORY.md)

## The gate

The compiler is the only dependency. No hardware, no vendor toolchain, no PlatformIO.

```bash
python tools/gate.py
```

That is the same command CI runs on Linux, Windows and macOS — deliberately, since a
second CI-only definition of "passing" is a definition that drifts. `make check` works
too and delegates to the same driver.

1600-odd assertions, compiled under `-Werror` with `-Wconversion
-Wsign-conversion -Wshadow`. It covers the decisions that would otherwise only be
discoverable on a rooftop:

- a Meshtastic **private** channel, which arrives wearing a sync word no table has ever
  seen and is rescued by the plaintext MeshHeader magic
- a frame where the sync word and the magic **disagree** — the magic wins, because it was
  read in-band from the same buffer
- a first byte of `0x40`, which is a valid MeshCore v1 header **and** a valid LoRaWAN
  MHDR. Reported as unknown rather than guessed at
- MeshCore's packed path-length byte, which is **not** a byte count: `0x45` is five hops
  of two-byte hashes and consumes ten bytes
- a reserved hash-size code of `0b11`, which is not four-byte hashes
- a frame the radio rejected at the preamble, from which **nothing** may be decoded
- an advert that promises a location and then stops, which is truncation and not (0, 0)
- a capture line whose text field contains `","proto":"meshcore"` — the forgery attempt
  the JSON escaper exists for
- a five-slot partition table on an 8 MB board, refused twice

## Layout

```
firmware/
  include/sniffer/   portable logic, no radio dependencies
  src/               those modules, plus radio/ and main.cpp
  partitions/        generated: triboot.csv, snifferboot.csv
tests/               the gate: C++ suites + the host tooling's own tests
tools/
  gate.py            the gate driver
  gen_layouts.py     regenerates the tables from the code's geometry
  flash.py           validating flasher
  sniffctl.py        the operator's CLI
docs/
```

The logic that decides *what a frame means* is free of radio dependencies, which is what
lets it run on a laptop — and the suites compile the firmware's **actual** translation
units rather than copies, so a test cannot pass while the firmware rots.
[ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Status

| Piece | State |
|---|---|
| `Protocol`, `Provenance` — vocabulary and reason taxonomy | done, tested |
| `RfPlan`, `PlanRegistry` — listen plan, three confidence levels | done, tested |
| `Classifier` — sync word, magic, structural fallback, ambiguity | done, tested |
| `MeshCoreFrame`, `MeshCorePayload` | done, tested |
| `MeshtasticFrame`, `Proto` — header, `Data`, plaintext text | done, tested |
| `LoRaWanFrame` — PHY header, join-request DevEUI | done, tested |
| `Fingerprint`, `Filter`, `Counters` | done, tested |
| `Record`, `Jsonl`, `Wire` — both capture forms | done, tested |
| `CaptureEngine` — the pipeline | done, tested |
| `DeviceTable` — the node list, two orderings | done, tested |
| `Transport`, `RingLog` — sinks that never block | done, tested |
| `MemoryBudget` — measured-at-boot fit | done, tested |
| `Beacon`, `TxLockout` — encode-only messages, the RX-only guarantee | done, tested |
| `CommandLine`, `Console` — one grammar, three destinations | done, tested |
| `SlotPlan`, `RfPlanSource` | done, tested |
| `tools/sniffctl.py`, `tools/flash.py` | done, tested |
| `firmware/platformio.ini` envs `heltec_v4_sniffer_standalone`, `..._beacon_standalone` | **compile and link for ESP32-S3** (PlatformIO, `ci.yml` job `firmware`); not flashed to hardware |
| `firmware/platformio.ini` envs `heltec_v4_sniffer`, `..._beacon` | defined; need arduino-esp32 3.x for the `littlefs` row in `triboot.csv` — see [SLOTS.md](docs/SLOTS.md) |
| `Sx1262Promiscuous` — the radio | **written, not verified against hardware** |
| `main.cpp` — bring-up, the boot log, the console loop | **compiles and links for ESP32-S3** (PlatformIO, both standalone envs, in CI); **not run on hardware** |
| BLE / WiFi transports | **declared, not implemented** |
| `save` / `load` of the console configuration | **refused out loud, not implemented** |
| a Reticulum decoder | **not vendored; frames land in the untraceable bucket** |

## Compliance

> [!WARNING]
> **A sniffer radiates nothing.** A beacon build does, and MeshCore ships a 50% software
> duty-cycle default, which is not a legal airtime budget at 869.525 MHz — the EU's
> harmonised table permits up to 500 mW e.r.p. in the 869.4–869.65 MHz non-specific SRD
> entry *subject to*, among other routes, a duty cycle not exceeding **10%**. Offering
> 50% or 100% proves the firmware *can* transmit at that rate. That is evidence of
> capability, not permission.

Nothing here is legal advice, and no firmware can certify an arbitrary board, amplifier,
antenna or installation.

## Documents

- [Architecture](docs/ARCHITECTURE.md) — how it fits together, and what is next
- [Attribution](docs/ATTRIBUTION.md) — the reason taxonomy, and finding the unknowns
- [Wire formats](docs/WIRE-FORMATS.md) — everything decoded, and what needs a key
- [RF plan](docs/RF-PLAN.md) — the shared carrier, and what a receiver cannot know
- [Slots](docs/SLOTS.md) — the layout, and standing in for the mesh
- [Devices](docs/DEVICES.md) — the node list and its two orderings
- [Memory](docs/MEMORY.md) — the tables, the profiles, the boot check
- [Transmit](docs/TRANSMIT.md) — the beacon build, and the RX-only guarantee

## Acknowledgements

Built on [MeshCore](https://meshcore.io) and [Meshtastic](https://meshtastic.org), and
designed to share a board with
[meshcore-meshtastic-heltec-v4](https://github.com/neohiro/meshcore-meshtastic-heltec-v4).
Neither project is modified; this is firmware and tooling that stands alongside them.

MIT. © 2026 neohiro
