# Wire formats

Every format this firmware decodes, what it can read without a key, and what it cannot.
Each entry states its source, because a decoder written from memory is a decoder that is
wrong somewhere and does not know it.

The rule applied throughout: **structure is not content.** Reading that a frame has a
MeshCore v1 header with a GRP_TXT payload tells you what a sender *claimed*. Reading that
an Ed25519 signature verifies tells you it is true. This sniffer does the first and not
the second, everywhere, without exception.

---

## MeshCore v1

**Source:** the MeshCore project's `docs/packet_format.md`, describing v1 as used by
firmware v1.12.0 and later.

```
[header][transport_codes?][path_length][path][payload]
```

One byte packs everything:

| Bits | Field | Values |
|---|---|---|
| 0–1 | route type | 00 transport-flood, 01 flood, 02 direct, 03 transport-direct |
| 2–5 | payload type | 00 REQ, 01 RESPONSE, 02 TXT_MSG, 03 ACK, 04 ADVERT, 05 GRP_TXT, 06 GRP_DATA, 07 ANON_REQ, 08 PATH, 09 TRACE, 0A MULTIPART, 0B CONTROL, 0F RAW_CUSTOM |
| 6–7 | payload version | 00 v1; 01–03 reserved |

**The path-length byte is not a byte count.** Bits 0–5 are the hop count, bits 6–7 are
the hash size minus one. `0x45` is five hops of two-byte hashes and consumes **ten**
bytes. `0b11` is *reserved*, not four-byte hashes — treating it as four would let a
corrupt frame pass with a plausible path length, so the parser refuses it.

This is the field most likely to be got wrong from memory, and it gets the most tests.

### Readable with no key

| Payload | What is read |
|---|---|
| `ADVERT` | public key (32 B), timestamp (4 B LE), signature (64 B, **read, never verified**), appdata flags, location, name |
| `GRP_TXT` | group flags, channel hash, **text in the clear** |
| `CONTROL` | the frame is named; the sub-format is not vendored and is not guessed at |

### Not readable with no key

`TXT_MSG`, `REQ`, `RESPONSE`, `ACK`, `PATH`, `ANON_REQ`, `TRACE`, `MULTIPART`,
`GRP_DATA`, `RAW_CUSTOM` — structure is named, content is declared unreadable. That is
`partial`, not `unattributed`, and the distinction is the whole triage taxonomy.

### Appdata flags

| Bit | Meaning |
|---|---|
| 0x01 | chat node |
| 0x02 | repeater |
| 0x03 | room server |
| 0x04 | sensor |
| 0x10 | has latitude/longitude |
| 0x20 | has feature 1 |
| 0x40 | has feature 2 |
| 0x80 | has name |

The role is a small set rather than a bitmask, so a node with two roles set is reported
as the higher one and the summary says nothing false about it.

A frame that promises a location and then stops is `truncated`. Reporting (0, 0) would
put null island on the operator's map.

---

## Meshtastic

**Source:** the Meshtastic project's protocol documentation and `PacketHeader`.

Meshtastic encrypts its payload and sends a 16-byte header in the clear. That is the
whole reason an unkeyed sniffer can say anything at all.

| Offset | Size | Field |
|---|---|---|
| `0x00` | 3 | magic `0x95 0x33 0x16`, in the clear |
| `0x03` | 1 | destination node id, low byte only |
| `0x04` | 4 | from (uint32 LE) |
| `0x08` | 4 | packet id (uint32 LE; also the AES-CTR nonce seed) |
| `0x0C` | 1 | flags |
| `0x0D` | 1 | channel hash |
| `0x0E` | 1 | next hop |
| `0x0F` | 1 | relay node |
| `0x10` | .. | encrypted payload, or a plaintext `Data` when the channel is primary |

Flags: bits 0–2 hop limit, bit 3 want-ack, bit 4 via-MQTT, bits 5–7 hop start.

**The hop distance is free.** Both hop limits are in the header, so hops travelled is
`hopStart - hopLimit`. On a flooding mesh that *is* the distance, and it is the
shortest-path signal for this protocol without a single decryption.

**Private channels are rescued by the magic.** A private channel derives its sync word
from the channel hash, so its frames arrive wearing a byte no table here has ever seen. A
sync-word-only design would drop every private frame. Three unambiguous plaintext bytes
at the front of the buffer do not.

### The `Data` protobuf

Read by a hand-written wire walker (`Proto.hpp`), not a protobuf library. Two reasons:
the schema is often not available — a frame on a channel nobody here holds a key for is
opaque by design — and a capture format whose whole value is that you can read it with
`cat` should not require a code generator to parse.

| Field | Type | Meaning |
|---|---|---|
| 1 | fixed32 | from |
| 2 | fixed32 | to |
| 3 | uint32 | channel |
| 4 | bytes | payload (the portnum-tagged application message) |
| 9 | bool | want_ack |
| 11 | int32 | hop_limit |

On the primary channel the body is a `Data` whose `payload` is a `PortNum` whose field 1
is the port number. For `TEXT_MESSAGE_APP` the rest is a message whose field 1 is the
text — so **a plaintext text message is readable with no key at all**, which is the case
that makes the decoder worth having.

An unknown field is skipped, not guessed at, and a skip that runs off the end is a
truncation rather than a shrug. A body beginning `0x01` is reported as
`encrypted-no-key`: a strong hint, not proof, and therefore not asserted.

---

## LoRaWAN PHY

**Source:** the LoRaWAN specification's PHY payload.

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | MHDR — MType (2b), Major (2b) |
| 1 | 2 | MACHeader — MType, Major, Minor |
| 3 | 4 | DevAddr (LE) |
| 7 | 1 | FCtrl — ADR, ADR_ACK_req, ACK, class B, downlink class |
| 8 | 2 | FCnt (LE) |
| 10 | 1 | FPort / FOptsLen |
| 11 | .. | FOpts, then FRMPayload |
| last 4 | 4 | MIC |

`JoinRequest` (MType 0) has none of that: it is MHDR then AppEUI (8), DevEUI (8),
DevNonce (2), MIC (4). **A join request carries a device identity in the clear**, which
is what makes surveying a frequency possible with no keys at all.

Major version 0 and 1 exist; anything above is refused rather than read on a guess.

A LoRaWAN frame on a community frequency is somebody's infrastructure, not a mesh node,
and every place this decoder appears says so — in the capture line, in the device-list
summary, and in `sniffctl.py --stats`.

---

## Reticulum

The sync word `0x42` is known. The RNode frame header is **not vendored here**.

`owningDecoder(Protocol::Reticulum)` returns `None` on purpose. Claiming a decoder that
does not exist would put a name in the capture stream that resolves to nothing, which is
worse than saying "none". Reticulum frames therefore land in the untraceable bucket with
`known-sync-unknown-body`, and that is a statement about this firmware's coverage, not
about the network.

---

## The capture formats

### JSONL — the archival form

One line per frame, one JSON object, no wrapping array, no footer. Appendable: a capture
still being written is valid, and every line already on disk is valid. One lost serial
byte costs one frame and desynchronises nothing.

```json
{"v":1,"seq":412,"t":123456,"proto":"MeshCore","net":"MeshCore EU868",
 "community":"MeshCore","conf":"carrier+sync+body","carrier_only":false,
 "attrib":"attributed","decoder":"meshcore.grp_txt","reason":"fully-decoded",
 "untraceable":false,"anomaly":false,"rssi":-103,"snr":-7.5,"sync":18,
 "sync_avail":true,"hdr":"ok","crc":"ok","why":"",
 "plan":"869.525/250/SF11/4-5","fp":"4b2e1f0a9c8d7e6f","rep":14,"len":6,
 "corrupt":false,"noise":false,"filtered":false,
 "decoded":{"mc_type":"grp_txt","chan":"0x8F","gflags":"0x00","text":"hello"},
 "data":"15 00 00 8f 68 69"}
```

Every line repeats `plan`, `att` — the listen plan — so a capture is **self-describing**:
a line lifted out of the middle of a log still says what the sniffer was listening for,
which is the thing a header-only format loses the moment the file is split or mailed.

`untraceable` and `anomaly` are derived booleans emitted by the firmware, so a host tool
never has to keep its own copy of the reason table in step with it.

**Escaping is a security property, not a formatting detail.** `text` and `name` come off
the air, from whoever was transmitting. A message containing a quote, a backslash or a
newline must not be able to end a line or forge a field — a captured MeshCore group
message containing `","proto":"meshcore","` is the first thing anybody does when they
notice their mesh is being logged. `jsonEscape()` handles it, and
`tests/test_capture_format.cpp` tests it directly rather than assuming.

### Wire — the compact form, for BLE

36-byte header, then the raw bytes, then the decoded fields as NUL-terminated pairs
closed by an empty key. Deliberately separate from the JSON: a phone can parse this
without a schema, and the two formats are optimised for opposite ends.

Every field carries its own length, because BLE notifications are not framed in a way
this can rely on and a stateful stream over a lossy link is a stream that
desynchronises. `magic` + `version` + `headerLen` + `totalLen` means a phone meeting a
future firmware with extra header fields skips them rather than misreading them.

SNR crosses as a signed 16-bit count of tenths of a decibel, clamped rather than
wrapped — a wrapped value reads as a plausible wrong one rather than as an error.
