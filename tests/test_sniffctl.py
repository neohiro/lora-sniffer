#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Tests for the host-side tools.

Three files, run by tools/gate.py:

    tests/test_sniffctl.py     the operator's CLI, and that it agrees with the firmware
    tests/test_flash_tool.py  the flasher's refusals, cross-checked against the C++
    tests/test_repo_hygiene.py the boring things that fail on a fresh Windows clone

The sniffctl tests do something the C++ suite cannot: they hold the Python
vocabulary to the same list as the C++ headers. A host tool that spells a reason
differently from the firmware is a host tool whose `--reason` filter silently matches
nothing, and the failure looks like a quiet band.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import sniffctl  # noqa: E402
import flash  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def header(name: str) -> str:
    """One firmware source file's contents as text, for the vocabulary cross-check.

    A host tool that spells a reason differently from the firmware is a host tool
    whose filter silently matches nothing, and the failure looks like a quiet band.

    Searches both trees: the enumerations are declared in `include/sniffer/*.hpp`, but
    `isUntraceable()` and the attribution table are in `src/*.cpp`. Looking only in one
    place meant the test either read the wrong file or raised FileNotFoundError.
    """
    for sub in ("include/sniffer", "src"):
        candidate = ROOT / "firmware" / sub / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    raise AssertionError(f"{name} is in neither firmware/include/sniffer nor firmware/src")


# Kept as an alias so the cross-check reads the same whichever name a reader reaches
# for first.
load_module = header


def jsonl(*records: dict) -> str:
    import json

    return "".join(json.dumps(r) + "\n" for r in records)


def data_rows(out: str) -> list[str]:
    """The device rows of a `--devices` report, without the summary lines.

    The summary line starts with a digit too ("3 node(s)   1 direct, ..."), so a
    selector that only checked `ln[0].isdigit()` returned the header as the first row
    and every ordering assertion after it was made against the wrong line. Matching on
    the protocol-tag column is what actually distinguishes a row: the index, then the
    tag, then the identity.
    """
    return [ln for ln in out.splitlines() if re.match(r"^\d+\s+(MC|MT|RT|LW|CX|\?\?)\s", ln)]


def base(**over) -> dict:
    rec = {
        "v": 1,
        "seq": 1,
        "t": 1000,
        "proto": "MeshCore",
        "net": "MeshCore EU868",
        "community": "MeshCore",
        "conf": "carrier+sync+body",
        "carrier_only": False,
        "attrib": "attributed",
        "decoder": "meshcore.grp_txt",
        "reason": "fully-decoded",
        "untraceable": False,
        "anomaly": False,
        "rssi": -100,
        "snr": -8.0,
        "sync": 18,
        "sync_avail": True,
        "hdr": "ok",
        "crc": "ok",
        "why": "",
        "plan": "869.525/250/SF11/4-5",
        "fp": "4b2e1f0a9c8d7e6f",
        "rep": 1,
        "len": 12,
        "corrupt": False,
        "noise": False,
        "filtered": False,
        "decoded": {},
        "data": "15 00 00 8f",
    }
    rec.update(over)
    return rec


class Parsing(unittest.TestCase):
    def test_reads_one_object_per_line(self):
        recs = list(sniffctl.read_records(jsonl(base(), base(seq=2)).splitlines(True)))
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[1]["seq"], 2)

    def test_blank_lines_are_not_errors(self):
        recs = list(sniffctl.read_records(["\n", jsonl(base()), "\n"]))
        self.assertEqual(len(recs), 1)

    def test_a_truncated_final_line_is_skipped_not_fatal(self):
        # A capture interrupted by a power cut ends mid-object. One bad line must not
        # cost the operator the other forty thousand.
        text = jsonl(*[base(seq=i) for i in range(50)])
        text += '{"seq":51,"proto":"MeshC'
        recs = list(sniffctl.read_records(text.splitlines(True)))
        self.assertEqual(len(recs), 51)
        self.assertEqual(sum(1 for r in recs if r.get("__bad__")), 1)

    def test_a_non_object_line_is_flagged(self):
        recs = list(sniffctl.read_records(["[1,2,3]\n"]))
        self.assertEqual(len(recs), 1)
        self.assertIn("__bad__", recs[0])


class Vocabulary(unittest.TestCase):
    """These two tests are the reason this file exists.

    They are what stops the firmware and its own tooling drifting apart, which is the
    failure that presents as "the filter does nothing" and gets an hour of the
    operator's time.
    """

    def test_reason_names_match_the_firmware(self):
        header = load_module("Provenance.cpp")
        missing = [name for name in sniffctl.REASONS if f'"{name}"' not in header]
        self.assertEqual(missing, [], f"reasons not found in Provenance.cpp: {missing}")

    def test_untraceable_set_matches_the_firmware(self):
        # The firmware's isUntraceable() is a switch listing these by name. If a
        # reason is added on one side only, --only-unknown and the device's own filter
        # would disagree about the same frame.
        header = load_module("Provenance.cpp")
        for name in sniffctl.UNTRACEABLE:
            self.assertIn(
                f"Reason::{self.reason_enum(name)}",
                header,
                f"{name} is in UNTRACEABLE but not in the firmware's isUntraceable()",
            )

    def test_protocol_names_match_the_firmware(self):
        header = load_module("Protocol.cpp")
        for name in sniffctl.PROTOCOLS:
            self.assertIn(f'"{name}"', header, f"protocol {name} missing from Protocol.cpp")

    @staticmethod
    def reason_enum(name: str) -> str:
        camel = "".join(part.capitalize() for part in name.split("-"))
        return camel

    def test_attribution_names_match_the_firmware(self):
        header = load_module("Provenance.cpp")
        for name in sniffctl.ATTRIBUTIONS:
            self.assertIn(f'"{name}"', header)


class Filtering(unittest.TestCase):
    def opts(self, argv: list[str]):
        args = sniffctl.build_parser().parse_args(argv)
        args.include_corrupt = not args.no_corrupt
        return sniffctl.Options(args)

    def rec(self, **over):
        return base(**over)

    def test_no_rules_passes_everything_but_still_hides_noise(self):
        o = self.opts(["-"])
        self.assertTrue(o.match(self.rec()))
        self.assertFalse(o.any_rule())
        # Noise and corruption are excluded by default, and that exclusion *is* a
        # narrowing rule -- so "no rules" means "no protocol/network/rssi rule", not
        # "literally everything". Asserting otherwise was wrong and hid the real
        # behaviour behind a nice-sounding assertion.
        self.assertFalse(o.match(self.rec(noise=True)))
        # Corruption is the opposite: shown unless `--no-corrupt`, because a frame that
        # failed its CRC is usually the reason an operator opened the capture at all.
        self.assertTrue(o.match(self.rec(corrupt=True)))
        self.assertFalse(self.opts(["-", "--no-corrupt"]).match(self.rec(corrupt=True)))

    def test_only_unknown_matches_exactly_the_firmware_set(self):
        o = self.opts(["-", "--only-unknown"])
        for reason in sniffctl.UNTRACEABLE:
            self.assertTrue(o.match(self.rec(reason=reason)), reason)
        for reason in sniffctl.REASONS:
            if reason not in sniffctl.UNTRACEABLE:
                self.assertFalse(o.match(self.rec(reason=reason)), reason)

    def test_only_unknown_excludes_encrypted_frames(self):
        # The distinction the whole triage design turns on: an encrypted frame was
        # *traced* to its protocol, only its content is unreadable.
        o = self.opts(["-", "--only-unknown"])
        self.assertFalse(o.match(self.rec(reason="encrypted-no-key")))
        self.assertFalse(o.match(self.rec(reason="meshcore-encrypted")))

    def test_only_anomalies(self):
        o = self.opts(["-", "--only-anomalies"])
        for reason in sniffctl.ANOMALIES:
            self.assertTrue(o.match(self.rec(reason=reason)), reason)
        self.assertFalse(o.match(self.rec(reason="foreign-sync-word")))

    def test_protocol_filter_accepts_tag_or_name(self):
        for spelling in ("MeshCore", "meshcore", "MC"):
            o = self.opts(["-", "--protocol", spelling])
            self.assertTrue(o.match(self.rec(proto="MeshCore")), spelling)

    def test_rssi_bounds_are_strict(self):
        below = self.opts(["-", "--rssi-below", "-90"])
        self.assertTrue(below.match(self.rec(rssi=-91)))
        self.assertFalse(below.match(self.rec(rssi=-90)))
        above = self.opts(["-", "--rssi-above", "-100"])
        self.assertTrue(above.match(self.rec(rssi=-99)))
        self.assertFalse(above.match(self.rec(rssi=-100)))

    def test_min_repeat(self):
        o = self.opts(["-", "--min-repeat", "5"])
        self.assertTrue(o.match(self.rec(rep=5)))
        self.assertFalse(o.match(self.rec(rep=4)))

    def test_fingerprint_is_exact(self):
        o = self.opts(["-", "--fingerprint", "4B2E1F0A9C8D7E6F"])
        self.assertTrue(o.match(self.rec()))
        self.assertFalse(o.match(self.rec(fp="0000000000000000")))

    def test_text_matches_any_decoded_value(self):
        o = self.opts(["-", "--text", "MAST"])
        self.assertTrue(o.match(self.rec(decoded={"name": "mast-7"})))
        self.assertFalse(o.match(self.rec(decoded={"name": "roof-2"})))

    def test_noise_hidden_unless_asked_for(self):
        o = self.opts(["-"])
        self.assertFalse(o.match(self.rec(noise=True)))
        o = self.opts(["-", "--include-noise"])
        self.assertTrue(o.match(self.rec(noise=True)))

    def test_corrupt_hidden_with_no_corrupt(self):
        o = self.opts(["-"])
        self.assertTrue(o.match(self.rec(corrupt=True)))
        o = self.opts(["-", "--no-corrupt"])
        self.assertFalse(o.match(self.rec(corrupt=True)))

    def test_rules_are_anded(self):
        o = self.opts(["-", "--protocol", "MeshCore", "--min-repeat", "5"])
        self.assertTrue(o.match(self.rec(rep=5)))
        self.assertFalse(o.match(self.rec(rep=4)))
        self.assertFalse(o.match(self.rec(rep=5, proto="Meshtastic")))


class Reports(unittest.TestCase):
    def style(self):
        return sniffctl.Style(False)

    def records(self, *recs):
        return list(sniffctl.read_records(jsonl(*recs).splitlines(True)))

    def test_stats_leads_with_the_untraceable_ratio(self):
        recs = self.records(*[base(seq=i) for i in range(7)] + [base(seq=100)])
        # The eighth is unattributable.
        recs = list(sniffctl.read_records(jsonl(*([base(seq=i) for i in range(7)]
                                                 + [base(seq=100, reason="foreign-sync-word",
                                                         attrib="unattributed",
                                                         untraceable=True)])).splitlines(True)))
        out = sniffctl.report_stats(recs, None, self.style())
        self.assertIn("untraceable ratio", out)
        self.assertIn("12%", out)  # 1 of 8
        self.assertIn("foreign-sync-word", out)

    def test_stats_explains_every_reason_it_prints(self):
        recs = list(sniffctl.read_records(jsonl(base(reason="truncated", anomaly=True)).splitlines(True)))
        out = sniffctl.report_stats(recs, None, self.style())
        self.assertIn("the frame ended before", out)

    def test_stats_warns_when_the_carrier_is_doing_all_the_work(self):
        recs = list(
            sniffctl.read_records(
                jsonl(*[base(seq=i, carrier_only=True, conf="carrier") for i in range(4)]).splitlines(True)
            )
        )
        out = sniffctl.report_stats(recs, None, self.style())
        self.assertIn("promiscuous", out)
        self.assertIn("docs/RF-PLAN.md", out)

    def test_stats_says_nothing_rather_than_zero_percent_when_empty(self):
        out = sniffctl.report_stats([], None, self.style())
        self.assertIn("n/a", out)

    def test_unknowns_groups_by_fingerprint(self):
        recs = list(
            sniffctl.read_records(
                jsonl(
                    *[base(seq=i, t=1000 * i, reason="foreign-sync-word", attrib="unattributed",
                          untraceable=True, fp="aaaa000000000001") for i in range(5)],
                    *[base(seq=100 + i, reason="no-evidence-at-all", attrib="unattributed",
                          untraceable=True, fp="bbbb000000000002") for i in range(2)],
                ).splitlines(True)
            )
        )
        out = sniffctl.report_unknowns(recs, None, self.style())
        self.assertIn("7 untraceable frames in 2 distinct shape(s)", out)
        self.assertIn("aaaa000000000001", out)
        self.assertIn("x5", out)
        self.assertIn("x2", out)
        # Grouping is the point: a cadence is the finding.
        self.assertIn("apart", out)

    def test_unknowns_says_so_when_there_is_nothing_unknown(self):
        recs = list(sniffctl.read_records(jsonl(base()).splitlines(True)))
        out = sniffctl.report_unknowns(recs, None, self.style())
        self.assertIn("nothing arrived that this firmware could not name", out)

    def test_devices_orders_by_shortest_path(self):
        # Distinct timestamps: with every fixture heard at the same instant, both
        # orderings fall through to the same tiebreak and agree by accident.
        def mt(node: int, hops: str, seq: int):
            return base(seq=seq, t=1000 * seq, proto="Meshtastic",
                        net="Meshtastic EU868 LongFast", community="Meshtastic",
                        decoder="meshtastic.meshheader",
                        decoded={"from": f"!{node:08x}", "hops": hops})

        recs = list(
            sniffctl.read_records(
                jsonl(
                    mt(1, "0a/00", 1),   # 10 hops, heard first
                    mt(2, "07/07", 2),   # 0 hops, adjacent
                    mt(3, "07/05", 3),   # 2 hops, heard last
                ).splitlines(True)
            )
        )
        out = sniffctl.report_devices(recs, "shortest-path", self.style(), 10)
        self.assertIn("!00000002", data_rows(out)[0])   # adjacent leads
        self.assertIn("!00000003", out)
        self.assertIn("1 direct", out)

        # Shortest path and last seen must disagree, or one of them is not implemented.
        by_seen = sniffctl.report_devices(recs, "last-seen", self.style(), 10)
        self.assertNotEqual(data_rows(out)[0], data_rows(by_seen)[0])

    def test_devices_puts_unknown_distance_last(self):
        # A MeshCore advert carries no path field. Treating that as adjacency is the
        # default-looking answer and it is a lie.
        advert = base(proto="MeshCore", decoder="meshcore.advert",
                      decoded={"key": "01020304", "name": "mast-7"})
        adjacent = base(seq=2, proto="Meshtastic", decoder="meshtastic.meshheader",
                        decoded={"from": "!00000009", "hops": "03/03"})
        recs = list(sniffctl.read_records(jsonl(advert, adjacent).splitlines(True)))
        out = sniffctl.report_devices(recs, "shortest-path", self.style(), 10)
        rows = data_rows(out)
        self.assertEqual(len(rows), 2)
        self.assertIn("hops=0", rows[0])
        self.assertIn("hops=?", rows[1])
        self.assertIn("with unknown distance", out)

    def test_devices_keeps_the_shortest_hearing_of_a_node(self):
        # A flood can go round the other way; a later, longer sighting must not push a
        # node down the list.
        def mt(seq: int, hops: str):
            return base(seq=seq, proto="Meshtastic", decoder="meshtastic.meshheader",
                        decoded={"from": "!00000005", "hops": hops})

        recs = list(sniffctl.read_records(jsonl(mt(1, "07/03"), mt(2, "07/00")).splitlines(True)))
        out = sniffctl.report_devices(recs, "shortest-path", self.style(), 10)
        # 7-3 = 4 hops, then 7-0 = 7. The shorter hearing wins, so 4 -- and specifically
        # not 7, which is what "the last thing we heard" would have reported.
        self.assertIn("hops=4", data_rows(out)[0])

    def test_devices_keys_on_protocol_and_identity_kind(self):
        # The same four bytes on two protocols are two different nodes, and that is
        # the premise of the whole hardware.
        mc = base(proto="MeshCore", decoder="meshcore.advert", decoded={"key": "deadbeef"})
        mt = base(seq=2, proto="Meshtastic", decoder="meshtastic.meshheader",
                  decoded={"from": "!deadbeef", "hops": "03/03"})
        recs = list(sniffctl.read_records(jsonl(mc, mt).splitlines(True)))
        out = sniffctl.report_devices(recs, "shortest-path", self.style(), 10)
        self.assertIn("2 node(s)", out)

    def test_devices_explains_an_empty_list(self):
        recs = list(sniffctl.read_records(jsonl(base()).splitlines(True)))
        out = sniffctl.report_devices(recs, "shortest-path", self.style(), 10)
        self.assertIn("no nodes named themselves", out)
        self.assertIn("group text message does not", out)


class LineRendering(unittest.TestCase):
    def test_shows_the_identifiers_that_matter(self):
        rec = base(decoded={"text": "hello mesh"}, rep=14)
        line = sniffctl.render_line(rec, sniffctl.Style(False), False)
        self.assertIn("MC", line)
        self.assertIn("MeshCore", line)
        self.assertIn("x14", line)
        self.assertIn("4b2e1f0a", line)
        self.assertIn("-100dBm", line)
        self.assertIn("hello mesh", line)

    def test_flags_a_carrier_only_verdict(self):
        line = sniffctl.render_line(base(carrier_only=True), sniffctl.Style(False), False)
        self.assertIn("carrier-only", line)

    def test_prefers_a_message_over_an_identifier(self):
        rec = base(decoded={"key": "01020304", "name": "mast-7", "text": "the actual message"})
        self.assertIn("the actual message", sniffctl.render_line(rec, sniffctl.Style(False), False))

    def test_reports_skipped_lines_rather_than_hiding_them(self):
        recs = list(sniffctl.read_records(jsonl(base(), "{oops\n")))
        out = sniffctl.render_table(recs, None, sniffctl.Style(False), False)
        self.assertIn("could not be parsed", out)

    def test_colour_is_off_when_not_a_terminal(self):
        self.assertEqual(sniffctl.Style(False).red("x"), "x")
        self.assertIn("\033[", sniffctl.Style(True).red("x"))


class Cli(unittest.TestCase):
    def run_cli(self, argv: list[str]) -> tuple[int, str]:
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        # Both streams: the CLI reports refusals on stderr, and a test that only
        # captures stdout sees them leak into the runner's output as if they were
        # failures.
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sniffctl.main(argv)
        return code, out.getvalue()

    def test_reasons_lists_the_taxonomy(self):
        code, out = self.run_cli(["--reasons"])
        self.assertEqual(code, 0)
        self.assertIn("fully-decoded", out)
        self.assertIn("UNTRACEABLE", out)

    def test_no_arguments_prints_help(self):
        code, out = self.run_cli([])
        self.assertEqual(code, 2)
        self.assertIn("usage", out.lower())

    def test_missing_file_is_an_error_not_a_traceback(self):
        code, _ = self.run_cli(["/nonexistent/capture.jsonl"])
        self.assertEqual(code, 2)

    def test_send_without_port_is_refused(self):
        code, _ = self.run_cli(["--send", "stats"])
        self.assertEqual(code, 2)


class FlashTool(unittest.TestCase):
    def test_parses_the_shipped_tables(self):
        for name in flash.TABLES:
            parts = flash.parse_csv(ROOT / "firmware" / "partitions" / f"{name}.csv")
            self.assertTrue(parts, name)
            flash.validate(parts, 16 * 1024 * 1024)

    def test_size_parser_matches_the_cpp_rules(self):
        self.assertEqual(flash.parse_size("0x200000"), 0x200000)
        self.assertEqual(flash.parse_size("2M"), 2 * 1024 * 1024)
        self.assertEqual(flash.parse_size("64K"), 64 * 1024)
        self.assertEqual(flash.parse_size("4096"), 4096)

    def test_refuses_a_table_that_overruns_a_smaller_flash(self):
        parts = flash.parse_csv(ROOT / "firmware" / "partitions" / "triboot.csv")
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 4 * 1024 * 1024)
        self.assertIn("past the", str(ctx.exception))

    def test_refuses_a_misaligned_app_partition(self):
        # The bootloader refuses this and logs nothing, so the board looks dead.
        parts = [
            flash.Part("bootloader", "app", "factory", 0x0, 0x7000, False),
            flash.Part("ota_0", "app", "ota_0", 0x31000, 0x200000, False),
            flash.Part("fs_sniffer", "data", "spiffs", 0x241000, 0x100000, False),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("64KB aligned", str(ctx.exception))

    def test_refuses_overlapping_partitions(self):
        parts = [
            flash.Part("bootloader", "app", "factory", 0x0, 0x7000, False),
            flash.Part("ota_0", "app", "ota_0", 0x30000, 0x200000, False),
            flash.Part("fs_sniffer", "data", "spiffs", 0x100000, 0x100000, False),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("overlaps", str(ctx.exception))

    def test_refuses_a_crossed_filesystem_pairing(self):
        # Meshtastic mounts LittleFS and MeshCore mounts SPIFFS. Handing either side
        # the other's type makes it format the wrong one on boot.
        parts = [
            flash.Part("bootloader", "app", "factory", 0x0, 0x7000, False),
            flash.Part("ota_0", "app", "ota_0", 0x30000, 0x200000, False),
            flash.Part("fs_meshcore", "data", "littlefs", 0x230000, 0x100000, False),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("fs_meshcore", str(ctx.exception))

    def test_refuses_duplicate_labels(self):
        parts = [
            flash.Part("bootloader", "app", "factory", 0x0, 0x7000, False),
            flash.Part("ota_0", "app", "ota_0", 0x30000, 0x200000, False),
            flash.Part("ota_0", "data", "spiffs", 0x230000, 0x100000, False),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("duplicate", str(ctx.exception))

    def test_refuses_a_slot_with_no_filesystem(self):
        parts = [
            flash.Part("bootloader", "app", "factory", 0x0, 0x7000, False),
            flash.Part("ota_0", "app", "ota_0", 0x30000, 0x200000, False),
        ]
        with self.assertRaises(flash.FlashError) as ctx:
            flash.validate(parts, 16 * 1024 * 1024)
        self.assertIn("filesystem partition", str(ctx.exception))

    def test_geometry_agrees_with_the_cpp_header(self):
        # The flasher and SlotPlan.cpp implement the same rules on purpose, so a new
        # user can be protected on a machine with no C++ compiler. They must not drift.
        header = (ROOT / "firmware" / "include" / "sniffer" / "SlotPlan.hpp").read_text(
            encoding="utf-8"
        )
        for name, expected in (
            ("kSlotStrideBytes", 0x300000),
            ("kSlotAppBytes", 0x200000),
            ("kSlotFsBytes", 0x100000),
            ("kFirstSlotOffset", 0x30000),
            ("kSnifferSlot", 2),
        ):
            import re

            m = re.search(rf"{name}\s*=\s*([^;]+);", header)
            self.assertIsNotNone(m, name)
            expr = m.group(1).strip()
            resolved = (
                int(expr, 16)
                if expr.lower().startswith("0x")
                else {
                    "kCoredumpOffset + kCoredumpSize": 0x20000 + 0x10000,
                }.get(expr, None)
            )
            if resolved is None:
                continue
            self.assertEqual(resolved, expected, f"{name} in the header")

        parts = flash.parse_csv(ROOT / "firmware" / "partitions" / "triboot.csv")
        sniffer = next(p for p in parts if p.label == "ota_2")
        self.assertEqual(sniffer.offset, 0x30000 + 2 * 0x300000)
        self.assertEqual(sniffer.size, 0x200000)
        fs = next(p for p in parts if p.label == "fs_sniffer")
        self.assertEqual(fs.offset, sniffer.offset + 0x200000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
