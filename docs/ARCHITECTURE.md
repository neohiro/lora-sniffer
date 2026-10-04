# Architecture

## What this is

A LoRa sniffer as its own flashable firmware, in its own slot, on a Heltec WiFi LoRa 32
V4 whose single SX1262 is also carrying somebody's mesh.

Three things make it possible to be honest about what arrives:

1. **Two protocols share one modulation in `EU_868`.** MeshCore's default and
   Meshtastic's LongFast are both 869.525 MHz, 250 kHz, SF11, 4/5. They differ by one
   preamble byte. See [RF-PLAN.md](RF-PLAN.md).

2. **Both protocols put something readable in the clear.** MeshCore sends adverts,
   group text and control frames unencrypted; Meshtastic sends a 16-byte header
   unencrypted whatever the payload is. An unkeyed sniffer is therefore not limited to
   counting bytes -- it can name senders, roles, channels and messages. See
   [WIRE-FORMATS.md](WIRE-FORMATS.md).

3. **Nothing needs to be guessed.** Every frame carries the name of the decoder that
   read it and a reason from a fixed taxonomy, so a frame nothing could read is a
   classified finding rather than a shrug. See [ATTRIBUTION.md](ATTRIBUTION.md).

## Status: read this before trusting anything

| Piece | State |
|---|---|
| `Protocol`, `Provenance` — vocabulary and the reason taxonomy | done, tested |
| `RfPlan`, `PlanRegistry` — what we listen for, and who else is on it | done, tested |
| `Classifier` — sync word, MeshHeader magic, structural fallback, ambiguity | done, tested |
| `MeshCoreFrame`, `MeshCorePayload` — v1 packets, adverts, group text | done, tested |
| `MeshtasticFrame`, `Proto` — 16-byte header, `Data`, plaintext text | done, tested |
| `LoRaWanFrame` — PHY header, and the DevEUI in a join request | done, tested |
| `Fingerprint` — repeat detection over raw bytes | done, tested |
| `Filter` — the triage grammar | done, tested |
| `Record`, `Jsonl`, `Wire` — the capture stream, both forms | done, tested |
| `Counters` — the unattributable ratio and its reason breakdown | done, tested |
| `CaptureEngine` — the pipeline, noise and corruption decided first | done, tested |
| `DeviceTable` — the node list, two orderings, fixed capacity | done, tested |
| `Transport`, `RingLog` — interchangeable sinks that never block | done, tested |
| `MemoryBudget` — measured-at-boot fit check | done, tested |
| `Beacon` — encode-only multi-network, multi-send messages | done, tested |
| `TxLockout` — the RX-only guarantee, enforced by the gate | done, tested |
| `CommandLine`, `Console` — one grammar, three destinations | done, tested |
| `SlotPlan` — the sniffer as slot 2, its own filesystem | done, tested |
| `RfPlanSource` — listening where the repeater it replaced listened | done, tested |
| `Sx1262Promiscuous` — the radio | **written, not verified against hardware** |
| `main.cpp` — bring-up, the boot log, the console loop | **compiles and links for ESP32-S3** (PlatformIO, both standalone envs, in CI); **not run on hardware** |
| BLE / WiFi transports | **declared, not implemented** |
| `save` / `load` of the console configuration | **refused out loud, not implemented** |

assertions pass. Compiled under `-Werror` with `-Wconversion -Wsign-conversion
-Wshadow`. Two things are outside *that* gate, and neither is outside CI: the radio path
needs RadioLib and a physical SX1262, and `main.cpp` needs Arduino. The `firmware` job in
`.github/workflows/ci.yml` builds both for the chip with PlatformIO, which is what catches
a wrong RadioLib signature, an `Arduino.h` include or a `loop()` the linker cannot find.

## Why it is built this way

The logic that decides *which mesh a frame belongs to*, *whether its structure is
readable*, *whether anything could be trusted about it* and *whether the operator wants
to see it* is free of radio dependencies. That buys three things:

1. **It runs on a laptop.** `python tools/gate.py` needs a C++ compiler and nothing
   else — no hardware, no vendor toolchain, no PlatformIO.

2. **It is the same code on device.** The suites compile the firmware's actual
   translation units. A test cannot pass while the firmware rots.

3. **The dangerous failures are caught before there is any RF.** Three of them are
   decisions rather than code, and all three were decisions somebody had to get right:

   - A frame the radio rejected at the preamble never became a payload, so parsing it
     would attribute structure to bytes nobody received. `CaptureEngine` decides
     corrupt and noise *before* anything is parsed, and the tests assert that nothing
     is decoded from such a frame.

   - A receiver cannot measure the sender's frequency, spreading factor or coding
     rate. It can only demodulate at what it was configured for. `RfPlan` is named for
     what it is -- the listen plan -- and `PlanRegistry` answers "who else could this
     be" at three explicitly separated levels of confidence rather than one answer.

   - A byte of `0x40` decomposes as a valid MeshCore v1 header *and* as a valid
     LoRaWAN MHDR. When both probes fit and no sync byte is available, `Classifier`
     reports `Unknown` and says so, rather than picking the likelier one.

## The one place this firmware is wrong about itself

The sniffer's central claim is that it reads the LoRa sync word per frame, which is
what lets it tell MeshCore from Meshtastic on a shared carrier.

**That depends on the radio handing the byte over, and the SX1262 in packet mode does
not.** It strips the sync word and reports only whether it matched the value the radio
was configured with. Promiscuous capture relaxes matching, but whether the preamble byte
itself reaches the host depends on the RadioLib path in use.

So the driver reports `syncWordAvailable = false` when it did not get one, and the
entire verdict chain degrades to `carrier`-only — visibly, in the capture stream, in
`sniffctl.py --stats`, and in the boot log. It does not substitute the configured
value, because that would report every frame on the band as MeshCore.

This is stated here, in `Sx1262Promiscuous.hpp`, in `Protocol.hpp` and in
`README.md` rather than being left to be discovered. `TODO(bring-up)` marks the exact
line. Until it is resolved and tested, `CarrierAndSync` and `CarrierSyncAndBody`
verdicts are unreachable in practice and the firmware is a carrier- and body-level
decoder.

## Layout

```
firmware/
  include/sniffer/    portable logic, no radio dependencies
    Protocol.hpp        the vocabulary; identical to the bridge project's
    Provenance.hpp      the decoder registry and the reason taxonomy
    RfPlan.hpp          the listen plan and the evidence a radio will swear to
    PlanRegistry.hpp    named networks, and three levels of confidence
    Classifier.hpp      which mesh, and why
    Proto.hpp           just enough protobuf to read a Data message
    MeshCoreFrame.hpp   the v1 packet format
    MeshCorePayload.hpp the plaintext payload classes
    MeshtasticFrame.hpp the 16-byte header and what follows it
    LoRaWanFrame.hpp    the PHY header
    Fingerprint.hpp     is this the same frame again
    Filter.hpp          the triage grammar
    Record.hpp          one frame, and everything known about it
    Jsonl.hpp           the capture format
    Wire.hpp            the compact form, for BLE
    Counters.hpp        the unattributable ratio
    Capture.hpp         the pipeline
    DeviceTable.hpp     the node list
    Transport.hpp       interchangeable sinks
    MemoryBudget.hpp    measured-at-boot fit
    Beacon.hpp          encode-only messages
    CommandLine.hpp     one grammar
    Console.hpp         command execution and rendering
    SlotPlan.hpp        the sniffer as slot 2
    RfPlanSource.hpp    where the listen plan comes from
    TxLockout.hpp       what this firmware is allowed to transmit
  src/                those modules, plus the radio and main.cpp
  partitions/         generated: triboot.csv, snifferboot.csv
tests/                the gate: C++ suites + the host tooling's own tests
tools/
  gate.py             the gate driver
  gen_layouts.py      regenerates the tables from the code's geometry
  flash.py            validating flasher
  sniffctl.py         the operator's CLI
docs/                this directory
```

`main.cpp` includes `Arduino.h` and is therefore not part of the host gate — only the
portable modules are. `Sx1262Promiscuous.cpp` is inside `#if defined(ARDUINO)` for the
same reason, and compiles to nothing outside it.

## What a capture record costs

Worth stating because it drives everything about the device tables:

| Thing | Bytes |
|---|---|
| One `Record` | ~1.9 KB |
| One decoded field entry | 112 |
| One capture ring line | 320 |
| One `BeaconFrame` | ~300 |
| `DeviceTable<64>` | ~6.5 KB |
| Working set, PSRAM profile (256 devices, 256 ring lines) | 116.5 KiB |

`MemoryBudget::workingSetBytes()` computes all of this from real `sizeof` at compile
time, so adding a table changes the number the boot check uses and there is no constant
to forget to bump. See [MEMORY.md](MEMORY.md).

## Next

In order, because each depends on the one before:

1. **Resolve the sync-byte question on hardware.** Read the preamble byte, or document
   conclusively that the part will not give it up. Everything about the confidence
   levels depends on the answer, and the answer is one register read.

2. **BLE and WiFi transports.** `Transport.hpp` already declares the interface and the
   dispatcher already refuses to block, so this is a `CaptureSink` implementation and
   nothing else. `Wire.hpp` is the compact framing, deliberately separate from the JSON
   so a phone can parse without a schema.

3. **`save` / `load`.** The console's filter and options, written to the sniffer's own
   filesystem slot. Refused out loud until then rather than silently ignored.

4. **A Reticulum decoder.** The sync word is known and the RNode header is not vendored.
   `owningDecoder()` returns `None` for it rather than claiming a decoder that does not
   exist, so Reticulum frames land in the untraceable bucket honestly.

5. **A desktop GUI over `sniffctl.py`.** The device list with both orderings, a live
   unattributable-ratio meter, and one-click filters. Every one of those already works
   from the command line; this is presentation.
