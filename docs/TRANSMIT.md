# Transmitting

The brief asks for a way to send a custom message to repeaters, with maximum reach, over
several mesh networks, several times. That capability exists — and it is a **separate
build**, for reasons worth stating before the mechanics.

## Two builds, not one compromise

A **sniffer** must be silent. Putting a passive device on a community frequency and
having it key up is a rule problem before it is a technical one, and "it only sends a
keep-alive" is how that happens.

A **beacon** is a real capability. Both requirements are legitimate and they are not
compatible in one image, so they are two images:

| | default build | beacon build |
|---|---|---|
| `SNIFFER_TX_CAPABLE` | `0` | `1` |
| radio and RadioLib receive path compiled | yes | yes |
| transmit call compiled | no | yes |
| can transmit before being told | **never** | no — needs arming |
| survives a reboot | — | **no** |
| boot log says | `rx-only` | `beacon-disarmed` |

Arming is a command, not a setting. A device that comes back after a power cut should be
silent, and the only way to be transmitting is to have been told to, this boot.

```bash
pio run -d firmware -e heltec_v4_sniffer_beacon_standalone -t upload
```

## The guarantee, and how it is kept

`mayTransmit()` is `constexpr false` **unconditionally** — not "false unless a build flag
says otherwise". A beacon build does not weaken it; it goes through a different function,
`BeaconTx::isArmed()`, which requires both the build flag *and* a runtime arming.

The two are separate on purpose. The build flag decides what **exists**; the arming
decides what is **permitted**. Conflating them is how a "transmit" option ends up on by
default, and the person who adds it is not the person who answers for it.

`tools/gate.py` greps every `.cpp` for transmit call sites outside an
`#if kBeaconBuild` guard, and fails if it finds one. So does it check that
`mayTransmit()` is still unconditionally `false`. A comment claiming the firmware never
transmits is worth nothing; this is a check that fails CI.

## What it will not do

**It will not encrypt.** An encoder that takes a key is an encoder that gets a key pasted
at it, and a sniffer has no business holding one. The beacon sends plaintext on MeshCore
and on Meshtastic's primary channel, which is what anybody does when they set a node up.

**It will not manage airtime.** `Beacon.cpp` holds no duty-cycle accounting, and that is
deliberate. Deciding when it is legal to transmit is a region question with a real answer
— the EU's 869.4–869.65 MHz non-specific SRD entry permits up to 500 mW e.r.p.
*subject to*, among other routes, a duty cycle not exceeding **10%** — and the sniffer's
plan may be tuned to a band it knows nothing about. `BeaconSchedule` holds what the
operator asked for; whether the region's budget permits it *now* is the transmit layer's
job, and it is a refusal rather than a guess.

> [!WARNING]
> **MeshCore ships a 50% software duty-cycle default.** That is not a legal airtime
> budget at 869.525 MHz. Offering 50% or 100% proves the firmware *can* transmit at that
> rate; that is evidence of capability, not permission.

**It will not transmit on a non-primary Meshtastic channel.** There is no plaintext body
for an encrypted channel, so that target is skipped with a count rather than producing a
frame whose body is quietly wrong.

## Maximum reach, per protocol

**MeshCore.** A `GRP_TXT` is a channel hash and some text, sent with a path length of
zero and flooded. Hop count is set by the *destination's* max hops in its own
configuration, not by the sender — so "maximum reach" from here means **let it flood**,
and that is what a zero-length path does:

```
header 0x15   v1, GRP_TXT, flood
path    0x00  no path: flooded
flags   0x00
chan    0x8F
text    ...
```

**Meshtastic.** A text message is a `Data` protobuf whose payload is a portnum-tagged
application message — all of which `Beacon.cpp` varint-encodes by hand, because that is
deterministic and testable. It is more work than MeshCore and it is still here rather
than in the radio layer where it could not be.

## Multi-network, multi-send

```bash
beacon hello there both chan=8F n=5 ms=7000
```

| Part | Meaning |
|---|---|
| `hello there` | the text |
| `mc` / `mt` / `both` | which network. Defaults to MeshCore alone |
| `chan=8F` | channel hash, MeshCore. Meshtastic is always the primary channel |
| `n=5` | repeats, clamped to 32 |
| `ms=7000` | interval, floored at 1500 ms |

The floors are not politeness. `n=200,ms=50` is 200 transmissions in ten seconds, which is
a denial-of-service tool and not a beacon, and `BeaconSchedule` clamps rather than
building it.

**Target-major ordering**: every network gets its first copy before any network gets its
second. A duty-cycle limit that stops the run halfway has still covered both networks.
The other ordering would put five copies on one mesh and nothing on the other, and the
operator would not notice until they wondered why nobody on the second mesh received
anything.

## Rejection is loud

```
beacon: n= wants a repeat count, got: lots
beacon: chan= wants a number from 0 to 255
beacon: no text left after the modifiers
beacon: not sent -- disarmed, or the airtime budget said no
```

And a beacon that *did* go out is counted, printed, and included in the capture
statistics — so a capture file says plainly that the device was not passive:

```
emitted
tx mode: beacon-armed
beacons emitted this boot: 5
beacon build: transmit path compiled in but disarmed; it stays silent until armed
```

That last sentence is deliberately the *disarmed* wording even when armed, because it is
printed by `emitted` and the operator should read the mode line, not this one.

## Testing

Every frame `Beacon.cpp` builds is round-tripped through the decoder that has to read it
on the other end, in `tests/test_beacon.cpp`. An encoder and a decoder that agree with
each other and disagree with the specification is a self-consistent bug; checking the
decoder catches the case where the encoder drifted.

```
beacon hello there both chan=8F n=5 ms=7000
  -> "hello there" stripped of modifiers and the network selector
  -> 6 frames: mc, mt, mc, mt, mc, mt
  -> the MeshCore copy reads back as a GRP_TXT with the text "hello there"
  -> the Meshtastic copy reads back as a plaintext TEXT_MESSAGE_APP from the right node
```

And the portable layer builds frames but **cannot transmit from a test binary** — the
only `TxSink` implementation there is a file. Nothing it builds can reach an antenna
from a laptop, which is the entire reason the frame construction could be tested to
exhaustion in the first place.
