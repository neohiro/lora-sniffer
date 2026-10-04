# RF plan, and what a receiver can and cannot know

## The claim, stated first

A receiver **cannot measure** the frequency, spreading factor or coding rate of an
incoming frame. It can only demodulate at the parameters it was configured with, and
then report a handful of per-frame facts: the sync byte (if the radio gives it up),
whether the header survived, whether the CRC survived, RSSI and SNR.

So this firmware names its central type `RfParams` and documents it as the **listen
plan** — what we asked the demodulator for — rather than presenting it as a
measurement. A sniffer that prints "this frame is 869.525 MHz SF11" is reporting its own
configuration and dressing it up as an observation.

The difference between those two sentences is the difference between a tool and a
rumour, and it is why `PlanVerdict` separates three confidence levels rather than
answering once:

| Level | Evidence | What it supports |
|---|---|---|
| `carrier` | the modulation matched a known network's plan | "this arrived on a carrier two communities share" |
| `carrier+sync` | plus a sync byte that matched | "this is one of them, specifically" |
| `carrier+sync+body` | plus a decoder that read it | "this is a MeshCore advert" |

`carrierOnly` is a separate flag on the verdict, not folded into the enum, because it is
the one thing an operator must be warned about and a flag is impossible to read past.

## The EU_868 finding

On the EU band the two community defaults are the *same* modulation:

| | MeshCore default | Meshtastic `EU_868` LongFast |
|---|---|---|
| frequency | 869.525 MHz | 869.525 MHz |
| bandwidth | 250 kHz | 250 kHz |
| spreading factor | 11 | 11 |
| coding rate | 4/5 | 4/5 |
| sync word | `0x12` | `0x2B` |

Identical on every field that decides whether two radios hear each other, and different
by one preamble byte. That single fact is why one radio can serve both meshes, and also
why `carrier` alone cannot separate them on this band — which is exactly what
`judge()` reports when no sync byte is available:

```
listening  869.525MHz 250kHz SF11 4/5 explicit crc
evidence   38 resting on carrier only
```

Off the EU it does not hold. On `US_915` the two defaults are 3.65 MHz apart, so a
sniffer tuned to one hears nothing of the other. `PlanRegistry` says so rather than
pretending otherwise, and `docs/RF-PLAN.md`'s sibling `rf-plans` table carries both.

## Promiscuous capture, and the part that is unresolved

In normal packet mode the SX1262 **strips the sync word and reports only whether it
matched the value the radio was configured with**. A radio locked to `0x12` is blind to
Meshtastic; a radio locked to `0x2B` is blind to MeshCore.

Promiscuous capture relaxes sync matching so every frame is delivered, and the modem's
sync-valid status bit then becomes evidence rather than a gate. That is the setting
this firmware requires, and `Sx1262Promiscuous::configure()` writes a wildcard sync word
with a comment saying that writing anything else is the mistake that produces a sniffer
which hears one mesh and nothing else.

**Whether the preamble byte itself reaches the host is the open question in this
project.** Several RadioLib paths expose it only through a status register, and some not
at all. The driver reports `syncWordAvailable = false` when it did not get one, and the
whole verdict chain degrades to `carrier`-only — visibly.

It does not substitute the configured value. Substituting it would report every frame
on the band as MeshCore, which is the worst available failure: confidently wrong, on
every frame, on a shared band.

`TODO(bring-up)` in `Sx1262Promiscuous.cpp` marks the exact line. Until it is resolved
and tested on hardware, `carrier+sync` and `carrier+sync+body` are unreachable in
practice and this firmware is a carrier- and body-level decoder. That is a working
sniffer — it decodes MeshCore and Meshtastic frames, builds the device list, and
produces the unattributable ratio — but the *network* attribution is the part still
waiting on a hardware answer.

## What the radio does report

| Fact | Source | Trust |
|---|---|---|
| sync valid | modem sync-valid status bit | strong when the radio runs promiscuous |
| header valid | header CRC | strong; implies the frame was internally coherent |
| CRC ok/fail | payload CRC | strong; a failure means these are not the bytes sent |
| RSSI | `getRSSI()` | strong |
| SNR | `getSNR()` | strong |
| sync byte | see above | **unresolved** |
| frequency / SF / BW of the sender | — | **not obtainable by any receiver** |

## One demodulator, one modulation at a time

The SX1262 demodulates at one bandwidth and one spreading factor. A frame sent at
anything else is, for practical purposes, **invisible** — very likely not detected at
all, and if detected, garbage.

This is the honest limit of "a sniffer sees all LoRa frames". It does not. It sees every
frame that arrives at *its* demodulation settings, and:

- on the EU band with a MeshCore repeater nearby, that is a large share of the
  interesting traffic;
- with a Meshtastic LongFast network on the same band, also that;
- at SF7/125 kHz, neither.

`--stats` distinguishes frames it could name from frames it could not, and the
`carrier only` line is the one that tells you whether the band is quiet or your
modulation settings are wrong. The two look identical from the outside; the flag is how
they are told apart.

There is no CAD-based scan to work around this. The SX1262's channel activity detection
cannot distinguish one protocol's preamble from another's, so scanning for activity and
switching modulation would be a scan for *anybody*, which on a shared band means a scan
for the loudest thing nearby.

## Transmitting

The default build **cannot transmit**. `mayTransmit()` is `constexpr false`
unconditionally, the transmit path is compiled out unless `-DSNIFFER_TX_CAPABLE=1`, and
`tools/gate.py` greps the sources for transmit calls outside that guard — so a future
`radio.transmit(...)` in an unguarded file fails CI rather than shipping.

A beacon build compiles the path but requires a runtime arming that does not survive a
reboot. Both facts are printed at boot before anything can transmit:

```
[tx] RX-only build: no transmit path is compiled in, so this device cannot key up
```

Beacon.cpp holds no airtime accounting, and that is deliberate. Deciding when it is
legal to transmit is a region question with a real answer — the EU's 869.4–869.65 MHz
non-specific SRD entry permits up to 500 mW e.r.p. *subject to*, among other routes, a
duty cycle not exceeding 10%, and the sniffer's plan may be tuned to a band it knows
nothing about. `BeaconSchedule` holds what the operator asked for; whether the region's
budget permits it *now* is the transmit layer's job, and it is a refusal rather than a
guess.

## Region defaults

`sniffer-sniffer` ships the `EU_868` plan as its default, because that is the one band
where the two community defaults coincide and where this tool has the most to say. For
anywhere else, set the frequency explicitly:

```bash
python tools/flash.py --table triboot ... # or
pio run -d firmware -e heltec_v4_sniffer_standalone -t upload \
  --project-option="build_flags=-DFREQUENCY_MHZ=906.875"
```

`resolvePlan()` reports where the plan came from on every boot — region default, imported
settings, build flags or a command-line override — and applies them in that order. See
[SLOTS.md](SLOTS.md) for why "imported settings" is second.

## Compliance

> [!WARNING]
> **Do not deploy this on a band you are not licensed for, and do not add a beacon
> without reading your region's rules.** A sniffer radiates nothing. A beacon build
> radiates, and MeshCore ships a 50% software duty-cycle default, which is not a legal
> airtime budget at 869.525 MHz — the EU's 10% duty-cycle limit applies there. Offering
> 50% or 100% proves the firmware *can* transmit at that rate. That is evidence of
> capability, not permission.

Nothing here is legal advice, and no firmware can certify an arbitrary board, amplifier,
antenna or installation.
