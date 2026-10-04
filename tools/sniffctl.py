#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""sniffctl -- the operator's side of a LoRa sniffer.

Reads the JSONL capture stream the firmware emits -- from a serial port, a file, or
stdin -- and answers the questions the sniffer exists to answer:

    sniffctl capture.jsonl                     a live, colourised table
    sniffctl --only-unknown capture.jsonl      only frames nothing could name
    sniffctl --stats capture.jsonl             where the airtime actually went
    sniffctl --devices capture.jsonl           the node list, shortest path first
    sniffctl --devices --order last-seen ...   the node list, most recent first
    sniffctl --unknowns capture.jsonl          unattributable frames, grouped
    sniffctl --port COM7 --baud 115200        live from a board
    sniffctl --send "devices" --port COM7     drive a board's console

Three design points that are the reason this is a script and not a GUI:

  * **`--stats` is the headline, not `--only-unknown`.** On a shared band the
    majority of what arrives is frequently not the network you care about. The
    number that tells you whether a band is interesting is the ratio of frames that
    could be named to frames that could not, and this prints it first.

  * **`--devices` is built here, not on the device.** The firmware keeps a bounded
    table so that `devices` works with no host attached; this reconstructs the same
    table from a capture file so that a capture taken yesterday can be interrogated
    today with no hardware at all. Both orderings are offered, because the brief
    asks for both and they answer different questions -- see docs/DEVICES.md.

  * **A frame that could not be named is never silently dropped.** It goes in the
    table with the reason, the fingerprint and the byte count, and `--unknowns`
    groups by fingerprint so a device transmitting on a timer is obvious rather
    than being forty separate curiosities.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Vocabulary, held in step with the firmware
# ---------------------------------------------------------------------------

# Mirrors firmware/include/sniffer/Protocol.hpp and Provenance.hpp. tests/
# test_sniffctl.py checks that these agree with the C++ headers, because a host
# tool that spells a reason differently from the firmware is a host tool whose
# filters silently match nothing.

PROTOCOLS = ["Unknown", "MeshCore", "Meshtastic", "Reticulum", "LoRaWAN", "Custom"]
PROTOCOL_TAGS = {
    "MeshCore": "MC",
    "Meshtastic": "MT",
    "Reticulum": "RT",
    "LoRaWAN": "LW",
    "Custom": "CX",
    "Unknown": "??",
}

_TAG_TO_NAME = {tag.lower(): name for name, tag in PROTOCOL_TAGS.items() if tag != "??"}


def _canonical_protocol(text: str) -> str:
    """`MC`, `mc` and `MeshCore` all mean MeshCore.

    The two-letter tags are what the firmware prints on an OLED column and in a log
    line, so they are what an operator's fingers reach for. Unknown text is returned
    lowercased rather than rejected here: an unmatched protocol should produce an empty
    result the operator can see, not a crash mid-pipeline.
    """
    return _TAG_TO_NAME.get(text.strip().lower(), text.strip().lower())

ATTRIBUTIONS = ["attributed", "partial", "unattributed"]

# The reason taxonomy, with the operator-facing explanation for each. Kept here so
# `--stats` can explain itself without the firmware having to send prose.
REASONS: dict[str, str] = {
    "fully-decoded": "a registered decoder parsed this and produced named fields",
    "encrypted-no-key": "header read; payload is ciphertext and no key is held for it",
    "meshcore-encrypted": "MeshCore header read; payload is encrypted, no key held",
    "truncated": "the frame ended before the structure it declares was complete",
    "reserved-value": "a field held a value the specification reserves",
    "corrupt-on-air": "the radio reported a CRC failure, so these bytes are not the bytes sent",
    "known-sync-unknown-body": "a sync word we name, but no decoder recognised the body",
    "foreign-sync-word": "a sync word no registry row has: most likely another community",
    "no-evidence-at-all": "no sync byte available and nothing in the bytes was conclusive",
    "anonymous-but-structured": "no sync byte, but the body is structured enough to be a protocol",
    "noise-or-too-short": "too short or below the noise floor to say anything",
}

# Reasons that mean "nothing in this firmware could put a name to the frame". This is
# the set the brief asks to be easy to find, and it is deliberately narrow: a frame
# that was recognised and then found encrypted was traced to its protocol, and
# lumping it in here would bury the interesting half.
UNTRACEABLE = {
    "foreign-sync-word",
    "known-sync-unknown-body",
    "no-evidence-at-all",
    "anonymous-but-structured",
    "noise-or-too-short",
}

ANOMALIES = {"truncated", "reserved-value", "corrupt-on-air", "known-sync-unknown-body"}


class SniffError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Colour
# ---------------------------------------------------------------------------

class Style:
    """ANSI, off when not a terminal or when --no-colour.

    Checked rather than assumed: piping into a file must not leave escape codes in
    a capture somebody intends to read in three months.
    """

    def __init__(self, enabled: bool) -> None:
        self.on = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.on else text

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)

    def for_attribution(self, attrib: str, text: str) -> str:
        return {"attributed": self.green, "partial": self.yellow, "unattributed": self.red}.get(
            attrib, self.dim
        )(text)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def read_records(stream: Iterable[str]) -> Iterator[dict]:
    """Yield one dict per capture line, skipping anything unparseable.

    Skipping rather than aborting is deliberate and is worth stating: a capture file
    is appendable and may have been truncated by a power cut, so its last line may
    be half an object. One unparseable line must not cost the operator the other
    forty thousand. The count is reported at the end so the loss is visible.
    """
    for raw in stream:
        line = raw.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            yield {"__bad__": line}
            continue
        if isinstance(rec, dict):
            yield rec
        else:
            yield {"__bad__": line}


def open_source(path: Optional[str], port: Optional[str], baud: int) -> Iterable[str]:
    """The capture source: a file, a serial port, or stdin.

    Serial needs pyserial, imported lazily so that reading a file works on a machine
    that will never have a board attached -- which is most machines, and certainly
    every CI runner.
    """
    if port:
        try:
            import serial  # type: ignore
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise SniffError(
                "reading a serial port needs pyserial: pip install pyserial"
            ) from exc
        ser = serial.Serial(port, baud, timeout=1)
        try:
            while True:
                raw = ser.readline()
                if raw:
                    yield raw.decode("utf-8", errors="replace")
                else:
                    time.sleep(0.01)
        finally:
            ser.close()

    if path in (None, "-"):
        return sys.stdin
    p = Path(path)
    if not p.is_file():
        raise SniffError(f"no such capture file: {p}")
    return p.open("r", encoding="utf-8", errors="replace")


def open_source_now(path: Optional[str], port: Optional[str], baud: int) -> Iterable[str]:
    """`open_source`, forced to run its body.

    This function is a generator, so *calling* it does nothing: the `open()` and the
    pyserial import only happen when the first line is pulled, which is inside the
    read loop rather than inside the `try` that was meant to catch it. A missing capture
    file therefore escaped as a traceback and a missing pyserial as an ImportError, both
    of which are exactly the case an operator needs explained rather than dumped.

    Draining a fresh generator to its first yield runs the validation; the generator is
    then discarded and a second one is handed back.
    """
    gen = open_source(path, port, baud)
    next(gen, None)
    gen.close()
    return open_source(path, port, baud)


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

class Options:
    """What the operator asked to see.

    An attribute rather than passing argparse's namespace around, because these are
    read in list comprehensions thousands of times a minute and clarity matters more
    than the microseconds.
    """

    def __init__(self, args: argparse.Namespace) -> None:
        self.only_unknown = args.only_unknown
        self.only_anomalies = args.only_anomalies
        # Accept a tag or a name, so `--protocol MC` and `--protocol meshcore` are the
        # same filter. A record always carries the full name, so comparing the operator's
        # spelling verbatim made the short form match nothing -- and an empty result on a
        # busy band looks exactly like a quiet band.
        self.protocol = (
            {_canonical_protocol(p).lower() for p in args.protocol}
            if args.protocol
            else None
        )
        self.network = {n.lower() for n in args.network} if args.network else None
        self.attribution = {a.lower() for a in args.attribution} if args.attribution else None
        self.reason = {r.lower() for r in args.reason} if args.reason else None
        self.rssi_below = args.rssi_below
        self.rssi_above = args.rssi_above
        self.min_repeat = args.min_repeat
        self.fingerprint = args.fingerprint.lower() if args.fingerprint else None
        self.text = args.text.lower() if args.text else None
        self.include_noise = args.include_noise
        self.include_corrupt = args.include_corrupt

    def any_rule(self) -> bool:
        return any(
            [
                self.only_unknown,
                self.only_anomalies,
                self.protocol,
                self.network,
                self.attribution,
                self.reason,
                self.rssi_below is not None,
                self.rssi_above is not None,
                self.min_repeat is not None,
                self.fingerprint,
                self.text,
            ]
        )

    def match(self, rec: dict) -> bool:
        if rec.get("__bad__"):
            return False
        if rec.get("noise") and not self.include_noise:
            return False
        if rec.get("corrupt") and not self.include_corrupt:
            return False
        if self.only_unknown and rec.get("reason") not in UNTRACEABLE:
            return False
        if self.only_anomalies and rec.get("reason") not in ANOMALIES:
            return False
        if self.protocol and str(rec.get("proto", "")).lower() not in self.protocol:
            return False
        if self.network:
            net = str(rec.get("community", rec.get("net", ""))).lower()
            if net not in self.network and str(rec.get("net", "")).lower() not in self.network:
                return False
        if self.attribution and str(rec.get("attrib", "")).lower() not in self.attribution:
            return False
        if self.reason and str(rec.get("reason", "")).lower() not in self.reason:
            return False
        rssi = rec.get("rssi")
        if isinstance(rssi, int):
            if self.rssi_below is not None and not rssi < self.rssi_below:
                return False
            if self.rssi_above is not None and not rssi > self.rssi_above:
                return False
        if self.min_repeat is not None and int(rec.get("rep", 1)) < self.min_repeat:
            return False
        if self.fingerprint and str(rec.get("fp", "")).lower() != self.fingerprint:
            return False
        if self.text:
            hay = " ".join(str(v) for v in (rec.get("decoded") or {}).values()).lower()
            if self.text not in hay:
                return False
        return True


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def decode_of(rec: dict) -> str:
    """The most informative decoded field, for a narrow table column.

    Ordered by how much an operator wants to read it: a message, then a node name,
    then a role, then whatever else exists. A table column wide enough for a message
    is not a table.
    """
    d = rec.get("decoded") or {}
    for key in ("text", "name", "role", "mc_type", "mtype", "why", "reason"):
        v = d.get(key)
        if v:
            return str(v)
    return ""


def render_line(rec: dict, style: Style, show_hex: bool) -> str:
    tag = PROTOCOL_TAGS.get(str(rec.get("proto", "Unknown")), "??")
    attrib = str(rec.get("attrib", "unattributed"))
    t = rec.get("t", 0)
    rssi = rec.get("rssi", 0)
    rep = rec.get("rep", 1)
    fp = str(rec.get("fp", ""))[:8]

    left = style.dim(f"{t:>9}") + " " + style.for_attribution(attrib, tag) + " "
    mid = f"{str(rec.get('net', '?'))[:22]:<22} "
    right = f"x{rep:<4} {fp:<8} {rssi:>5}dBm"
    if rec.get("carrier_only"):
        right += " " + style.yellow("carrier-only")

    summary = decode_of(rec)
    line = left + mid + right
    if summary:
        line += "  " + summary[:64]
    if show_hex and rec.get("data"):
        line += style.dim("  " + str(rec["data"])[:32])
    return line


def render_table(records: list[dict], opts: Options, style: Style, show_hex: bool) -> str:
    bad = sum(1 for r in records if r.get("__bad__"))
    lines = [render_line(r, style, show_hex) for r in records if not r.get("__bad__")]
    out = "\n".join(lines)
    if bad:
        out += (
            "\n"
            + style.yellow(
                f"note: {bad} line(s) could not be parsed and were skipped. A capture "
                "interrupted mid-write ends in a partial line; everything before it is intact."
            )
        )
    return out


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

def report_stats(records: list[dict], opts: Options, style: Style) -> str:
    good = [r for r in records if not r.get("__bad__")]
    noise = [r for r in good if r.get("noise")]
    analysed = [r for r in good if not r.get("noise")]
    untraceable = [r for r in analysed if r.get("reason") in UNTRACEABLE]
    corrupt = [r for r in good if r.get("corrupt")]

    def pct(n: int, d: int) -> str:
        return f"{(100.0 * n / d):.0f}%" if d else "n/a"

    out: list[str] = []
    out.append(style.bold("frames"))
    out.append(
        f"  {len(good):>8} total      {len(analysed):>8} analysed   {len(noise):>8} noise"
    )
    out.append(
        f"  {len(corrupt):>8} corrupt    {len(untraceable):>8} untraceable"
    )
    out.append("")

    # The headline. Everything else in this tool exists to explain it.
    out.append(style.bold("attribution"))
    by_attrib = collections.Counter(str(r.get("attrib", "unattributed")) for r in analysed)
    for name in ATTRIBUTIONS:
        out.append(f"  {name:<24} {by_attrib.get(name, 0):>8}  {pct(by_attrib.get(name, 0), len(analysed)):>5}")
    ratio = pct(len(untraceable), len(analysed))
    out.append("")
    out.append(
        style.bold("  untraceable ratio")
        + f"      {style.for_attribution('unattributed', ratio)}   "
        + f"({len(untraceable)} of {len(analysed)} analysed frames)"
    )
    if analysed and not untraceable:
        out.append(
            "  " + style.green("everything arriving could be named by a decoder in this firmware")
        )
    out.append("")

    out.append(style.bold("reasons"))
    by_reason = collections.Counter(str(r.get("reason", "?")) for r in analysed)
    if not by_reason:
        out.append("  (nothing analysed)")
    for name, n in by_reason.most_common():
        out.append(f"  {name:<24} {n:>8}  {pct(n, len(analysed)):>5}  {REASONS.get(name, '')}")
    out.append("")

    out.append(style.bold("protocol"))
    by_proto = collections.Counter(str(r.get("proto", "Unknown")) for r in analysed)
    for name, n in by_proto.most_common():
        out.append(f"  {PROTOCOL_TAGS.get(name, '??')} {name:<20} {n:>8}  {pct(n, len(analysed)):>5}")
    out.append("")

    out.append(style.bold("evidence"))
    carrier_only = sum(1 for r in analysed if r.get("carrier_only"))
    no_sync = sum(1 for r in analysed if not r.get("sync_avail"))
    corrupt_crc = sum(1 for r in analysed if r.get("crc") == "bad")
    out.append(f"  {carrier_only:>8} resting on the carrier alone")
    out.append(f"  {no_sync:>8} with no sync byte available")
    out.append(f"  {corrupt_crc:>8} with a CRC failure the radio reported")
    if carrier_only and analysed and carrier_only * 2 > len(analysed):
        out.append("")
        out.append(
            "  "
            + style.yellow(
                "more than half of these frames were identified from the carrier alone.\n"
                "  that means the radio is not in promiscuous mode: the preamble byte is\n"
                "  being stripped, so the two meshes sharing this band cannot be told apart\n"
                "  even when the body would decode. See docs/RF-PLAN.md"
            )
        )
    return "\n".join(out)


def report_unknowns(records: list[dict], opts: Options, style: Style) -> str:
    """Unattributable frames, grouped by fingerprint.

    Grouping is the whole point. Forty separate unattributable frames are a curiosity;
    forty byte-identical ones on a fixed cadence are a device, and that is the single
    most useful thing this tool can tell an operator.
    """
    rows = [r for r in records if not r.get("__bad__") and r.get("reason") in UNTRACEABLE]

    groups: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for r in rows:
        groups[(str(r.get("fp", "")), str(r.get("reason", "")))].append(r)

    ordered = sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True)

    out: list[str] = []
    out.append(
        style.bold(f"{len(rows)} untraceable frames in {len(ordered)} distinct shape(s)")
    )
    out.append(
        style.dim(
            "grouped by fingerprint: identical bytes arriving repeatedly are one sender, "
            "not many"
        )
    )
    out.append("")

    for (fp, reason), group in ordered[:40]:
        rssi = [int(r.get("rssi", 0)) for r in group if isinstance(r.get("rssi"), int)]
        times = sorted(int(r.get("t", 0)) for r in group)
        span = (times[-1] - times[0]) / 1000.0 if len(times) > 1 else 0.0

        cadence = ""
        if span > 0 and len(times) > 1:
            gap = span / (len(times) - 1)
            cadence = f"~{gap:.1f}s apart"

        head = group[0]
        line = (
            style.bold(f"!{fp}")
            + f"  x{len(group)}"
            + f"  {style.dim(reason)}"
            + f"  rssi {min(rssi) if rssi else '?'}..{max(rssi) if rssi else '?'} dBm"
        )
        if cadence:
            line += style.dim(f"  {cadence}")
        out.append(line)
        out.append(
            "    "
            + style.dim(f"net={head.get('net')} sync={head.get('sync')} "
                        f"carrier={'yes' if head.get('carrier_only') else 'no'} "
                        f"len={head.get('len')}")
        )
        why = (head.get("decoded") or {}).get("why")
        if why:
            out.append("    " + style.dim(str(why)))
        data = head.get("data")
        if data:
            out.append("    " + style.dim(f"hex {data}"))
        out.append("")

    if len(ordered) > 40:
        out.append(style.dim(f"... and {len(ordered) - 40} more"))
    if not ordered:
        out.append(style.green("nothing arrived that this firmware could not name"))
    return "\n".join(out)


# ---------------------------------------------------------------------------
# The device list
# ---------------------------------------------------------------------------

class DeviceTable:
    """Rebuilt from a capture, with the same two orderings as the firmware.

    Kept in step with firmware/include/sniffer/DeviceTable.hpp: four bytes of identity,
    protocol *and* identity-kind as the key, hop count tracked as "unknown" rather than
    "zero", and eviction of the least recently seen node. Those three are the parts
    that change the answer, and all three are asserted by the C++ suite as well.
    """

    def __init__(self, capacity: int = 256) -> None:
        self.capacity = capacity
        self.devices: "collections.OrderedDict[tuple[str, str, bytes], dict]" = (
            collections.OrderedDict()
        )

    @staticmethod
    def identity_of(rec: dict) -> tuple[bytes, str] | None:
        """Pull a node identity out of a decoded record, if it names one.

        Returns None rather than a guess: a MeshCore GRP_TXT has a channel and a
        sender we cannot see, and inventing an entry for it would put a phantom node
        in the operator's list.
        """
        proto = str(rec.get("proto", ""))
        d = rec.get("decoded") or {}

        if proto == "MeshCore":
            key = d.get("key")
            if key:
                try:
                    return bytes.fromhex(str(key))[:4], "meshcore-key"
                except ValueError:
                    return None
            return None

        if proto == "Meshtastic":
            src = d.get("from")
            if isinstance(src, str) and src.startswith("!"):
                try:
                    return int(src[1:], 16).to_bytes(4, "little"), "meshtastic-node"
                except ValueError:
                    return None
            return None

        if proto == "LoRaWAN":
            addr = d.get("devaddr")
            if addr:
                try:
                    return bytes.fromhex(str(addr))[:4], "lorawan-devaddr"
                except ValueError:
                    return None
            return None

        return None

    @staticmethod
    def hops_of(rec: dict) -> tuple[bool, int]:
        """Hop distance when the protocol exposes one.

        Meshtastic puts both the original hop limit and the current one in its header,
        so the distance travelled is their difference. MeshCore's group frames carry a
        path length of zero because the sender does not know it, so an advert's hop
        count is *unknown*, not zero -- which is why the flag is returned separately.
        """
        d = rec.get("decoded") or {}
        if rec.get("proto") == "Meshtastic":
            hops = d.get("hops")
            if isinstance(hops, str):
                try:
                    # "<original>/<remaining>", both hex: the distance travelled is the
                    # difference. Not masked to three bits: the hop *field* is three bits,
                    # but masking the difference turned a ten-hop hearing into "2 hops",
                    # which is a wrong answer rather than a rounded one.
                    original, _, remaining = hops.partition("/")
                    return True, max(0, int(original, 16) - int(remaining, 16))
                except ValueError:
                    return False, 0
            if isinstance(hops, int):
                return True, hops
        return False, 0

    def add(self, rec: dict) -> None:
        found = self.identity_of(rec)
        if found is None:
            return
        ident, kind = found
        key = (str(rec.get("proto", "")), kind, ident)

        valid, hops = self.hops_of(rec)
        name = (rec.get("decoded") or {}).get("name")
        text = (rec.get("decoded") or {}).get("text")

        if key in self.devices:
            dev = self.devices[key]
            dev["frames"] += 1
            dev["last"] = rec.get("t", 0)
            if valid and (not dev["hops_valid"] or hops < dev["hops"]):
                dev["hops"], dev["hops_valid"] = hops, True
            if isinstance(rec.get("rssi"), int) and (
                not dev["rssi_valid"] or rec["rssi"] > dev["rssi"]
            ):
                dev["rssi"], dev["rssi_valid"] = rec["rssi"], True
            if text and not dev["text"]:
                dev["text"] = str(text)
            self.devices.move_to_end(key)
            return

        if len(self.devices) >= self.capacity:
            self.devices.popitem(last=False)

        self.devices[key] = {
            "proto": key[0],
            "kind": kind,
            "id": ident,
            "hops": hops,
            "hops_valid": valid,
            "first": rec.get("t", 0),
            "last": rec.get("t", 0),
            "frames": 1,
            "rssi": rec.get("rssi", 0),
            "rssi_valid": isinstance(rec.get("rssi"), int),
            "role": (rec.get("decoded") or {}).get("role", ""),
            "name": str(name) if name else "",
            "text": str(text) if text else "",
        }

    def sorted(self, order: str) -> list[dict]:
        """Order the list.

        `shortest-path` puts unknown distance last rather than first, because an
        unattributable frame has no path field at all and treating that as adjacency
        is the default-looking answer and a lie. `last-seen` answers "what just started
        talking", which is a different question and is what you want the moment
        something appears.
        """
        rows = list(self.devices.values())
        if order == "last-seen":
            rows.sort(key=lambda d: (-d["last"], d["id"]))
        elif order == "frames":
            rows.sort(key=lambda d: (-d["frames"], -d["last"], d["id"]))
        else:
            rows.sort(
                key=lambda d: (
                    0 if d["hops_valid"] else 1,
                    d["hops"] if d["hops_valid"] else 0,
                    -d["last"],
                    d["id"],
                )
            )
        return rows


def render_identity(proto: str, kind: str, raw: bytes) -> str:
    """The node's identifier the way the mesh's own tooling writes it.

    Identities are held internally as little-endian bytes, which is convenient for
    comparing two of them and unreadable for a human. Printing `raw.hex()` therefore
    showed `02000000` for the node everybody on the network calls `!00000002` -- and an
    operator cross-referencing the device list against a node they can see in another
    client has no way to connect the two.

    A Meshtastic node id is `!` followed by the 32-bit id in network byte order.
    MeshCore identifies a node by a public key, and LoRaWAN by a device address; both
    are shown as the plain hex they are, with the kind already carrying which.
    """
    if kind == "meshtastic-node" and len(raw) == 4:
        return f"!{int.from_bytes(raw, 'little'):08x}"
    return raw.hex()


def report_devices(records: list[dict], order: str, style: Style, limit: int) -> str:
    table = DeviceTable()
    for r in records:
        table.add(r)
    rows = table.sorted(order)
    shown = rows[:limit]

    direct = sum(1 for d in rows if d["hops_valid"] and d["hops"] == 0)
    within3 = sum(1 for d in rows if d["hops_valid"] and d["hops"] <= 3)
    unknown = sum(1 for d in rows if not d["hops_valid"])

    out: list[str] = []
    out.append(
        style.bold(f"{len(rows)} node(s)")
        + style.dim(
            f"   {direct} direct, {within3} within 3 hops, {unknown} with unknown distance"
        )
    )
    out.append(style.dim(f"ordered by {order}"))
    out.append("")

    now = max((d["last"] for d in rows), default=0)
    for i, d in enumerate(shown):
        hops = str(d["hops"]) if d["hops_valid"] else "?"
        ident = render_identity(d["proto"], d["kind"], d["id"])
        bits = [f"{i:<3}", PROTOCOL_TAGS.get(d["proto"], "??"), f"{ident:<10}", f"hops={hops:<3}"]
        if d["rssi_valid"]:
            bits.append(f"rssi={d['rssi']:>5}")
        if d["role"]:
            bits.append(f"role={d['role']}")
        if d["name"]:
            bits.append(f"name={d['name']}")
        bits.append(f"x{d['frames']}")
        if d["last"]:
            bits.append(style.dim(f"{(now - d['last']) / 1000.0:.0f}s ago"))
        out.append(" ".join(bits))
        if d["text"]:
            out.append(style.dim(f"      last: {d['text'][:70]}"))

    if len(rows) > limit:
        out.append(style.dim(f"... and {len(rows) - limit} more (--limit to see them)"))
    if not rows:
        out.append(
            style.dim(
                "no nodes named themselves in this capture. A MeshCore advert or a "
                "Meshtastic header is what puts a node on this list; a group text "
                "message does not, because the format does not say who sent it."
            )
        )
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Driving a board
# ---------------------------------------------------------------------------

def send_command(port: str, baud: int, command: str, wait: float, style: Style) -> int:
    """Send one console command and print whatever comes back.

    One command at a time, with a fixed settle time. A board that offered a
    bidirectional protocol here would be more elegant and would also be one more thing
    to keep in step with the firmware; the console grammar is the same either way, and
    a person can type the same thing by hand when the script is not running.
    """
    try:
        import serial  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SniffError("sending commands needs pyserial: pip install pyserial") from exc

    ser = serial.Serial(port, baud, timeout=0.2)
    try:
        ser.reset_input_buffer()
        ser.write((command.rstrip("\r\n") + "\n").encode("utf-8"))
        deadline = time.time() + wait
        got = 0
        while time.time() < deadline:
            raw = ser.readline()
            if raw:
                sys.stdout.write(raw.decode("utf-8", errors="replace"))
                got += 1
            else:
                time.sleep(0.02)
        if got == 0:
            print(
                style.yellow(
                    f"no reply from {port} within {wait:g}s. Is the board running this "
                    "firmware, and is the console enabled?"
                ),
                file=sys.stderr,
            )
            return 1
        return 0
    finally:
        ser.close()


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="sniffctl",
        description="Read, triage and drive a LoRa sniffer capture stream.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  sniffctl capture.jsonl                     live table\n"
            "  sniffctl --only-unknown capture.jsonl      frames nothing could name\n"
            "  sniffctl --stats capture.jsonl             where the airtime went\n"
            "  sniffctl --devices capture.jsonl           nodes, shortest path first\n"
            "  sniffctl --devices --order last-seen       nodes, most recent first\n"
            "  sniffctl --unknowns capture.jsonl          unattributable, grouped\n"
            "  sniffctl --port COM7                       live from a board\n"
            "  sniffctl --port COM7 --send 'devices'      ask a board\n"
        ),
    )
    ap.add_argument("capture", nargs="?", help="a JSONL capture file, or - for stdin")
    ap.add_argument("--port", help="serial port to read live from")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--send", help="send one console command to --port and print the reply")

    ap.add_argument("--stats", action="store_true", help="the attribution and reason summary")
    ap.add_argument("--devices", action="store_true", help="the node list")
    ap.add_argument("--unknowns", action="store_true", help="untraceable frames, grouped")
    ap.add_argument(
        "--order",
        choices=["shortest-path", "last-seen", "frames"],
        default="shortest-path",
        help="device list ordering (default: shortest-path)",
    )
    ap.add_argument("--limit", type=int, default=40, help="rows to print (default: 40)")

    ap.add_argument("--only-unknown", action="store_true", help="only frames nothing could name")
    ap.add_argument("--only-anomalies", action="store_true", help="only malformed captures")
    ap.add_argument("--protocol", action="append", help="protocol name or tag; repeatable")
    ap.add_argument("--network", action="append", help="network community; repeatable")
    ap.add_argument("--attribution", action="append", help="attributed/partial/unattributed")
    ap.add_argument("--reason", action="append", help="a reason name from --reasons")
    ap.add_argument("--rssi-below", type=int, help="strictly weaker than this, in dBm")
    ap.add_argument("--rssi-above", type=int, help="strictly stronger than this, in dBm")
    ap.add_argument("--min-repeat", type=int, help="minimum sighting count of the fingerprint")
    ap.add_argument("--fingerprint", help="exact 16-hex-digit fingerprint")
    ap.add_argument("--text", help="case-insensitive substring of any decoded value")
    ap.add_argument("--include-noise", action="store_true", help="include below-floor frames")
    ap.add_argument("--no-corrupt", action="store_true", help="hide CRC-failed frames")

    ap.add_argument("--hex", action="store_true", help="show the raw bytes of each frame")
    ap.add_argument("--no-colour", action="store_true", help="never emit ANSI colour")
    ap.add_argument("--reasons", action="store_true", help="list every reason and exit")
    ap.add_argument("--limit-bytes", type=int, default=0, help="stop after this many records")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if args.no_colour or not sys.stdout.isatty():
        args.no_colour = True
    style = Style(not args.no_colour)

    if args.reasons:
        print(style.bold("reasons, and which are untraceable"))
        for name in REASONS:
            mark = style.red("UNTRACEABLE") if name in UNTRACEABLE else ""
            anomaly = style.yellow("anomaly") if name in ANOMALIES else ""
            tags = " ".join(t for t in (mark, anomaly) if t)
            print(f"  {name:<24} {REASONS[name]}")
            if tags:
                print(f"  {'':<24} {tags}")
        return 0

    if args.send:
        if not args.port:
            print("error: --send needs --port", file=sys.stderr)
            return 2
        try:
            return send_command(args.port, args.baud, args.send, 3.0, style)
        except SniffError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    if args.capture is None and not args.port:
        ap.print_help()
        return 2

    # --no-corrupt is the negation of an include-by-default, which argparse cannot
    # express directly without leaving the default True and every caller having to
    # remember to invert it.
    args.include_corrupt = not args.no_corrupt
    opts = Options(args)

    try:
        source = open_source_now(args.capture, args.port, args.baud)
    except SniffError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    records: list[dict] = []
    try:
        for rec in read_records(source):
            if opts.match(rec):
                records.append(rec)
            if args.limit_bytes and len(records) >= args.limit_bytes:
                break
    except KeyboardInterrupt:
        # Ctrl-C is the normal way to stop a live capture, so it is a clean exit.
        pass
    finally:
        if hasattr(source, "close"):
            source.close()

    if args.stats:
        print(report_stats(records, opts, style))
    elif args.devices:
        print(report_devices(records, args.order, style, args.limit))
    elif args.unknowns:
        print(report_unknowns(records, opts, style))
    else:
        if not records and opts.any_rule():
            print(
                style.yellow(
                    "nothing matched. Every filter rule is an AND, so a filter that is too "
                    "narrow looks exactly like a silent band -- try removing one rule."
                ),
                file=sys.stderr,
            )
        print(render_table(records, opts, style, args.hex))

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SniffError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(2)
    except BrokenPipeError:  # pragma: no cover - `sniffctl ... | head`
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
