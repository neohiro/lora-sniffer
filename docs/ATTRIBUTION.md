# Attribution, and the frames nothing can name

This document is about the part of the brief that is easy to skip and impossible to
add later: **a sniffer that prints hex has failed**, because on a shared band the
frames nobody can explain are usually the interesting ones.

## The registry

Every frame this firmware prints carries the name of the decoder that read it. Not a
protocol — a *decoder*, so an operator can say "the meshcore decoder read it" rather
than merely "we think it was MeshCore".

| Decoder id | Reads |
|---|---|
| `meshcore.v1` | the MeshCore v1 packet: header, path geometry, payload extent |
| `meshcore.advert` | an ADVERT's key, timestamp, role, location and name |
| `meshcore.grp_txt` | a GRP_TXT's channel hash, flags and text |
| `meshcore.control` | names a CONTROL frame; does not parse the sub-format |
| `meshtastic.meshheader` | the 16-byte plaintext header |
| `meshtastic.data` | the `Data` protobuf, when the body is plaintext |
| `lorawan.phy` | MHDR, MAC header, FHDR, FPort, and a join request's DevEUI |
| `none` | nothing claimed the frame |

These strings are a contract. They appear verbatim in the capture stream and in saved
reports, and `tests/test_sniffctl.py` checks them against `Provenance.hpp` so the host
tool and the firmware cannot spell one differently and have the mismatch present as a
filter that silently matches nothing.

## The three states

| State | Means |
|---|---|
| `attributed` | a decoder parsed the frame and produced named fields |
| `partial` | a decoder recognised the frame as its own and could not read past a point |
| `unattributed` | no decoder claimed the frame |

`partial` is the state that is easy to skip and matters most. A MeshCore group text
frame is `attributed`; a MeshCore encrypted text message is `partial`. Both are frames
we *named*. Only the second bucket is a finding about the frequency.

## The reason taxonomy

Eleven reasons, enumerated rather than free-text, because a fixed set can be counted,
filtered, alerted on and tested. A single `unknown` bucket would hide the three cases
that want completely different responses from an operator.

| Reason | Untraceable? | Anomaly? | What it means |
|---|:--:|:--:|---|
| `fully-decoded` | | | a decoder parsed this and produced named fields |
| `encrypted-no-key` | | | header read; payload is ciphertext and no key is held |
| `meshcore-encrypted` | | | MeshCore header read; payload is encrypted, no key held |
| `truncated` | | ✓ | the frame ended before the structure it declares was complete |
| `reserved-value` | | ✓ | a field held a value the specification reserves |
| `corrupt-on-air` | | ✓ | the radio reported a CRC failure, so these bytes are not the bytes sent |
| `known-sync-unknown-body` | ✓ | ✓ | a sync word we name, but no decoder recognised the body |
| `foreign-sync-word` | ✓ | | a sync word no registry row has — most likely another community |
| `no-evidence-at-all` | ✓ | | no sync byte available and nothing in the bytes was conclusive |
| `anonymous-but-structured` | ✓ | | no sync byte, but the body is structured enough to be a protocol |
| `noise-or-too-short` | ✓ | | too short, or below the noise floor, to say anything |

Three distinctions the table makes deliberately, because collapsing any of them is the
failure this document exists to prevent:

**Encrypted is not untraceable.** An encrypted Meshtastic frame was traced to
Meshtastic; only its content is unreadable, and the operator already knows why. Putting
it in the untraceable bucket buries the genuinely-unknown frames under a flood of frames
that are behaving exactly as designed.

**A foreign sync word is not an anomaly.** It is the *expected* outcome on a shared band
for any community that is not us. It is a finding, and `sniffctl.py --stats` reports it
under its own line, but calling it an anomaly would mean an operator in a dense city
sees a permanent warning and learns to ignore the warning.

**Unknown distance is not zero distance.** A frame with no path field is not a frame
from a node next door. `DeviceTable` keeps `hopsValid` separate from `hops` for exactly
this reason, and sorts unknown distance *last* — putting it first would be the
default-looking answer and it would be a lie.

## Finding them

Three ways, all the same set.

From the board:

```
filter untraceable=true
stats
```

From a saved capture:

```
sniffctl --only-unknown capture.jsonl
sniffctl --stats capture.jsonl
sniffctl --unknowns capture.jsonl
```

And the derived boolean is in the capture stream itself, so a host tool never has to
keep its own copy of this table in step with the firmware:

```json
{"reason":"foreign-sync-word","untraceable":true,"anomaly":false, ...}
```

## Grouping is the point

One unattributable frame is a curiosity. Forty byte-identical ones on a fixed cadence
are a device, and that is the most useful single thing a sniffer can tell you.

`--unknowns` groups by fingerprint and prints the cadence:

```
7 untraceable frames in 2 distinct shape(s)

!aaaa000000000001  x5  foreign-sync-word  rssi -101..-98 dBm  ~30.0s apart
    net=unlisted network sync=153 carrier=yes len=8
    a sync word 0x99 belongs to no network this firmware has a row for, and the body
    matched nothing. On a shared band this is most likely another community, which is
    a finding rather than a fault
    hex 40 c3 19 8a 44 05 00 1b
```

The fingerprint covers the raw bytes and the sync byte, and deliberately **not** the
RSSI, the timestamp or any packet counter. Including those would give every repeat a
fresh identity, which is precisely the failure the fingerprint exists to prevent. It is
FNV-1a, 64-bit, and the reason it is not something stronger is that this is not a
security boundary — it groups frames for a human and has to run in microseconds on a
microcontroller that is also printing to a serial port.

## What a decoder is not allowed to do

Every rule here exists because the opposite is a way to be confidently wrong.

- **A decoder never verifies a signature.** A decoded advert says what a sender
  *claimed*. Whether the signature over that claim checks out is a question for the
  protocol stack holding the key. A sniffer that implied otherwise would be a forgery
  kit.

- **A decoder never reports `fully-decoded` for a structure it did not read.** If the
  sub-format is not vendored, the frame is named and the body is declared unparsed.
  `meshcore.control` is the worked example: the frame is identified as CONTROL and the
  sub-format is not guessed at.

- **A decoder never substitutes one field for another.** A MeshCore advert's
  promised-but-absent location is `truncated`, not (0, 0). Null island is not a place.

- **A wildcard sync byte never decides anything.** Promiscuous capture reports `0x00`
  when no real preamble byte matched. A byte that carries no information must not be
  able to contradict anything, and `Classifier`, `PlanRegistry` and `MeshCoreFrame` all
  treat it as absent rather than as "somebody else's".

- **A frame the radio refused is never decoded.** A frame rejected at the preamble
  never became a payload, so parsing it would attribute structure to bytes nobody
  received. `CaptureEngine` decides this *first*.

## On "the minilib"

The brief asks for messages that cannot be traced back to *the protocol stack inside the
LoRa device* — the `minilib`-backed crypto and packet implementation behind MeshCore's
v1 format, and the AES-CCM behind Meshtastic's MeshHeader.

What this repository makes precise is the **registry of decoders**: a frame is traceable
when one of the registered decoders can parse it, and the decoder's id is recorded so
the claim is checkable rather than implied.

A frame that cannot be traced falls into one of exactly four cases, and the taxonomy
above gives each its own reason:

1. **We hold no key.** `encrypted-no-key`, `meshcore-encrypted`. Expected, not a bug.
2. **A private or diverged channel.** `known-sync-unknown-body` — a sync word we name,
   a body no decoder claims.
3. **Another community.** `foreign-sync-word`. The single most likely outcome in a city.
4. **Nothing recognisable at all.** `no-evidence-at-all`, `anonymous-but-structured`.

If the brief meant something narrower by "minilib" — a specific library boundary
rather than "the protocol stack" — the registry is the single place to change. Adding a
decoder is one enumerator in `Provenance.hpp`, one row in `Provenance.cpp`, and one parse
function. Nothing else moves.
