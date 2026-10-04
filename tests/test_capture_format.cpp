// SPDX-License-Identifier: MIT
//
// Fingerprints, the JSONL capture format, the compact wire format, and counters.
//
// The JSON tests here are not pedantry. `text` and `name` come off the air, from
// whoever was transmitting, and this file is the only thing standing between a
// captured MeshCore group message and somebody's terminal emulator. A message
// containing a quote, a backslash or a newline must not be able to forge a field or
// end a line -- so those cases are tested directly rather than assumed.

#include <cmath>
#include <cstring>
#include <string>

#include "harness.hpp"
#include "sniffer/Counters.hpp"
#include "sniffer/Fingerprint.hpp"
#include "sniffer/Jsonl.hpp"
#include "sniffer/Record.hpp"
#include "sniffer/Wire.hpp"

using namespace sniff;

namespace {

Record sampleRecord() {
  Record r;
  r.seq = 412;
  r.timestampMs = 123456;
  r.link.rssiDbm = -103;
  r.link.snrDb = -7.5f;
  r.link.syncWord = 0x12;
  r.link.syncWordAvailable = true;
  r.link.syncWordCheck = Check::Passed;
  r.link.headerCheck = Check::Passed;
  r.link.crcCheck = Check::Passed;

  r.listenPlan.frequencyMHz = 869.525f;
  r.listenPlan.bandwidthKHz = 250.0f;
  r.listenPlan.spreadingFactor = 11;

  r.protocol = Protocol::MeshCore;
  r.verdict = judge(r.listenPlan, r.link, Protocol::MeshCore, true);
  r.provenance = attribute(DecoderId::MeshCoreGroupText, Reason::FullyDecoded);
  r.fingerprint = 0x4b2e1f0a9c8d7e6fULL;
  r.repeatCount = 14;

  const std::uint8_t data[] = {0x15, 0x00, 0x00, 0x8F, 'h', 'i'};
  r.length = static_cast<std::uint8_t>(sizeof(data));
  for (std::size_t i = 0; i < sizeof(data); ++i) r.data[i] = data[i];

  r.decoded.add("mc_type", "grp_txt");
  r.decoded.add("chan", "0x8F");
  r.decoded.add("text", "hello");
  return r;
}

// Search a NUL-separated field region for a byte sequence.
//
// strstr is the wrong tool here and returns a wrong answer rather than an error: the
// region's fields are NUL-*terminated*, so a C-string search stops at the end of the
// first field and never sees the second. An earlier version of this test used strstr
// and reported a field that was demonstrably present as missing.
bool containsField(const char* hay, std::size_t hayLen, const char* needle) {
  const std::size_t n = std::strlen(needle);
  if (n == 0 || hayLen < n) return false;
  for (std::size_t i = 0; i + n <= hayLen; ++i) {
    if (std::memcmp(hay + i, needle, n) == 0) return true;
  }
  return false;
}

std::string lineOf(const Record& r) {
  char buf[kMaxJsonLineBytes];
  const std::size_t n = toJsonLine(r, buf, sizeof(buf));
  CHECK_MSG(n > 0, "the record must fit the buffer the format advertises");
  return std::string(buf, n);
}

}  // namespace

void suite_fingerprint() {
  harness::suite("Fingerprint");

  // --- determinism ---------------------------------------------------------

  {
    const std::uint8_t a[] = {1, 2, 3, 4, 5};
    const std::uint8_t b[] = {1, 2, 3, 4, 5};
    CHECK_MSG(fingerprintBytes(a, sizeof(a)) == fingerprintBytes(b, sizeof(b)),
              "the same bytes must always give the same value, or the operator's grouping "
              "is worthless across a reboot");
  }
  {
    // The empty frame still fingerprints. A zero-length capture is a real state.
    const std::uint8_t none[1] = {0};
    CHECK(fingerprintBytes(none, 0) == kFnvOffsetBasis);
    CHECK(fingerprintBytes(nullptr, 10) == kFnvOffsetBasis);
  }
  {
    const std::uint8_t a[] = {1, 2, 3};
    const std::uint8_t b[] = {1, 2, 4};
    CHECK(fingerprintBytes(a, sizeof(a)) != fingerprintBytes(b, sizeof(b)));
  }
  {
    // The sync byte is part of the identity. Two frames with identical payloads on
    // different sync words are two different things on one frequency, and merging
    // them would hide exactly the collision an operator is hunting for.
    const std::uint8_t body[] = {9, 9, 9};
    const std::uint64_t mc = fingerprintFrame(body, sizeof(body), kMeshCoreSync, true);
    const std::uint64_t mt = fingerprintFrame(body, sizeof(body), kMeshtasticPublicSync, true);
    CHECK_MSG(mc != mt, "identical payloads on different networks are different frames");
  }
  {
    // A wildcard must not collide with a real 0x00. Merging them would be a silent
    // bug in exactly the case the module exists to handle.
    const std::uint8_t body[] = {7, 7, 7};
    const std::uint64_t none = fingerprintFrame(body, sizeof(body), 0x00, false);
    const std::uint64_t wildcard = fingerprintFrame(body, sizeof(body), 0x00, true);
    CHECK_MSG(none != wildcard, "'no sync byte' and 'wildcard sync byte' must differ");
  }
  {
    // RSSI, timestamps and counters must not be part of the identity, or every
    // repeat of the same device would look like a new device.
    const std::uint8_t body[] = {1, 2, 3};
    CHECK(fingerprintFrame(body, sizeof(body), 0x12, true) ==
          fingerprintFrame(body, sizeof(body), 0x12, true));
  }

  // --- hex rendering --------------------------------------------------------

  {
    CHECK(toHex64(0) == "0000000000000000");
    CHECK(toHex64(0xFFFFFFFFFFFFFFFFULL) == "ffffffffffffffff");
    CHECK(toHex64(0x4b2e1f0a9c8d7e6fULL) == "4b2e1f0a9c8d7e6f");
    CHECK_MSG(toHex64(0x5aULL).size() == 16, "fixed width, so it sorts and diffs");
  }

  // --- the repeat table -------------------------------------------------------

  {
    FingerprintTable t;
    CHECK_EQ(t.size(), 0u);

    CHECK_EQ(t.observe(0xAAAA), 1u);
    CHECK_EQ(t.observe(0xAAAA), 2u);
    CHECK_EQ(t.observe(0xBBBB), 1u);
    CHECK_EQ(t.observe(0xAAAA), 3u);
    CHECK_EQ(t.countOf(0xAAAA), 3u);
    CHECK_EQ(t.countOf(0xBBBB), 1u);
    CHECK_EQ(t.countOf(0xCCCC), 0u);
    CHECK_EQ(t.size(), 2u);

    std::uint64_t hash = 0;
    std::uint32_t count = 0;
    CHECK(t.mostRepeated(&hash, &count));
    CHECK_EQ(hash, 0xAAAA);
    CHECK_MSG(count == 3, "the most-repeated fingerprint is the one a timer-driven "
                          "device is talking through");

    t.clear();
    CHECK_EQ(t.size(), 0u);
    CHECK_MSG(!t.mostRepeated(&hash, &count), "an empty table has no most-repeated");
  }
  {
    // Overflowing the table evicts rather than refusing to record. A sniffer that
    // stopped counting after 64 distinct frames would be worse than one that
    // forgets the oldest.
    FingerprintTable t;
    for (std::size_t i = 0; i < FingerprintTable::kCapacity + 10; ++i) {
      CHECK_MSG(t.observe(static_cast<std::uint64_t>(i)) == 1, "a new fingerprint counts one");
    }
    CHECK_EQ(t.size(), FingerprintTable::kCapacity);
  }
  {
    // The oldest sighting is evicted first, which is the node least likely to be
    // heard again.
    FingerprintTable t;
    for (std::size_t i = 0; i < FingerprintTable::kCapacity; ++i) {
      t.observe(static_cast<std::uint64_t>(i));
    }
    // Touch the oldest so it is no longer the oldest.
    t.observe(0);
    t.observe(static_cast<std::uint64_t>(FingerprintTable::kCapacity));
    CHECK_EQ(t.countOf(0), 2u);
    CHECK_MSG(t.countOf(1) == 0u, "the previously-oldest entry was the one evicted");
  }
}

void suite_record() {
  harness::suite("Record");

  {
    DecodedFields f;
    CHECK_EQ(f.count, 0);

    CHECK(f.add("key", "value"));
    CHECK(f.find("key") != nullptr);
    CHECK_MSG(std::strcmp(f.find("key")->value, "value") == 0, "");
    CHECK(f.find("missing") == nullptr);

    CHECK(f.addHex("chan", 0x8F, 2));
    CHECK_MSG(std::strcmp(f.find("chan")->value, "0x8F") == 0, "hex fields keep their padding");
    CHECK(f.addFloat("snr", -7.5, 1));
    CHECK(std::strcmp(f.find("snr")->value, "-7.5") == 0);
    CHECK(f.add("n", 42ul));
    CHECK(std::strcmp(f.find("n")->value, "42") == 0);

    // A long value is truncated, not dropped: a half-shown value beats a silently
    // missing one.
    const std::string huge(500, 'x');
    CHECK(f.add("long", huge.c_str()));
    CHECK(f.find("long") != nullptr);
    CHECK_MSG(std::strlen(f.find("long")->value) < DecodedFields::kValueBytes,
              "the copy is bounded");

    f.clear();
    CHECK_EQ(f.count, 0);
  }
  {
    // The table is fixed capacity. Overrunning it is refused, not written past.
    DecodedFields f;
    std::size_t added = 0;
    for (std::size_t i = 0; i < DecodedFields::kMaxFields + 5; ++i) {
      if (f.add("k", "v")) ++added;
    }
    CHECK_EQ(added, DecodedFields::kMaxFields);
    CHECK_EQ(f.count, static_cast<std::uint8_t>(DecodedFields::kMaxFields));
  }
  {
    const Record r = sampleRecord();
    char buf[320];
    describeRecord(r, buf, sizeof(buf));
    const std::string s(buf);
    CHECK_MSG(s.find("000412") == 0, "the sequence number leads");
    CHECK_MSG(s.find("MC") != std::string::npos, "the protocol tag is on the line");
    CHECK_MSG(s.find("grp_txt") != std::string::npos, "so is what it says");
    CHECK_MSG(s.find("x14") != std::string::npos, "and how often this exact frame has been seen");
    CHECK_MSG(s.find("4b2e1f0a9c8d7e6f") != std::string::npos, "and its fingerprint");
    CHECK_MSG(s.find("rssi=-103") != std::string::npos, "");
  }
}

void suite_jsonl() {
  harness::suite("Jsonl");

  // --- the shape of a line -----------------------------------------------------

  {
    const std::string line = lineOf(sampleRecord());
    CHECK_MSG(line.back() == '\n', "one record, one line, newline terminated");
    CHECK_MSG(line.find('\n') == line.size() - 1, "and exactly one newline in it");
    CHECK_MSG(line.front() == '{' && line[line.size() - 2] == '}', "one JSON object");

    // The keys the host tool depends on.
    const char* required[] = {"\"v\":",     "\"seq\":",  "\"proto\":", "\"net\":",
                              "\"conf\":",  "\"rssi\":", "\"snr\":",   "\"sync\":",
                              "\"crc\":",   "\"plan\":", "\"fp\":",    "\"rep\":",
                              "\"len\":",   "\"data\":", "\"decoded\":", "\"reason\":",
                              "\"attrib\":", "\"untraceable\":", "\"carrier_only\":"};
    for (const char* k : required) {
      CHECK_MSG(line.find(k) != std::string::npos, k);
    }
    CHECK_MSG(line.find("\"v\":1") == line.find("\"v\":"), "the format version comes first");
  }

  // --- escaping: the reason this file exists ------------------------------------

  {
    char out[64];
    CHECK_EQ(jsonEscape("plain", out, sizeof(out)), 5u);
    CHECK(std::strcmp(out, "plain") == 0);

    jsonEscape("say \"hi\"", out, sizeof(out));
    CHECK_MSG(std::strcmp(out, "say \\\"hi\\\"") == 0, "quotes are escaped");

    jsonEscape("back\\slash", out, sizeof(out));
    CHECK(std::strcmp(out, "back\\\\slash") == 0);

    jsonEscape("line\nbreak", out, sizeof(out));
    CHECK_MSG(std::strcmp(out, "line\\nbreak") == 0,
              "a newline would end the line and forge a record");

    jsonEscape("tab\there", out, sizeof(out));
    CHECK(std::strcmp(out, "tab\\there") == 0);

    jsonEscape(std::string(1, '\x01').c_str(), out, sizeof(out));
    CHECK_MSG(std::strcmp(out, "\\u0001") == 0, "control bytes go out as \\u00XX");

    jsonEscape(nullptr, out, sizeof(out));
    CHECK(std::strcmp(out, "") == 0);
  }
  {
    // The attack this prevents: a captured message that tries to close the string
    // and forge fields. This is not hypothetical -- it is what anybody does when they
    // notice their mesh is being logged.
    Record r = sampleRecord();
    r.decoded.add("text", "\",\"proto\":\"meshcore\",\"reason\":\"fully-decoded");

    const std::string line = lineOf(r);

    // Exactly one proto key in the whole line. The forged one sits inside the decoded
    // text value and every quote in it is escaped, so it cannot become a field.
    std::size_t keys = 0;
    for (std::size_t at = line.find("\"proto\":"); at != std::string::npos;
         at = line.find("\"proto\":", at + 1)) {
      ++keys;
    }
    CHECK_MSG(keys == 1, "a text value must not be able to create a second field");
    CHECK_MSG(line.find("\\\"") != std::string::npos, "the quote was escaped");
    CHECK_MSG(line.find("\"reason\":\"fully-decoded\"") != std::string::npos,
              "and the real reason field is intact");
  }
  {
    // A text field full of newlines must not split the record.
    Record r = sampleRecord();
    r.decoded.add("text", "a\nb\nc\nd");
    const std::string line = lineOf(r);
    std::size_t newlines = 0;
    for (char c : line) {
      if (c == '\n') ++newlines;
    }
    CHECK_MSG(newlines == 1, "one line out, whatever went in");
  }

  // --- the header fields that make a capture self-describing ---------------------

  {
    // No sync byte: the line must say so rather than print 0x00.
    Record r = sampleRecord();
    r.link.syncWordAvailable = false;
    r.link.syncWord = 0x00;
    const std::string line = lineOf(r);
    CHECK_MSG(line.find("\"sync_avail\":false") != std::string::npos, "");
  }
  {
    // A carrier-only verdict is visible in the line, which is what makes "why can
    // this tool not tell the two meshes apart" answerable from a saved capture.
    Record r = sampleRecord();
    r.link.syncWordAvailable = false;
    r.verdict = judge(r.listenPlan, r.link, Protocol::Unknown, false);
    const std::string line = lineOf(r);
    CHECK_MSG(line.find("\"carrier_only\":true") != std::string::npos, "");
    CHECK_MSG(line.find("\"conf\":\"carrier\"") != std::string::npos, "");
  }
  {
    Record r = sampleRecord();
    r.corrupt = true;
    r.filtered = true;
    r.noise = true;
    const std::string line = lineOf(r);
    CHECK(line.find("\"corrupt\":true") != std::string::npos);
    CHECK(line.find("\"filtered\":true") != std::string::npos);
    CHECK(line.find("\"noise\":true") != std::string::npos);
  }
  {
    // An untraceable frame carries the derived boolean, so a host tool never has to
    // keep its own copy of the reason table in step with the firmware.
    Record r;
    r.protocol = Protocol::Unknown;
    r.provenance = attribute(DecoderId::None, Reason::ForeignSyncWord);
    r.decoded.add("reason", "foreign-sync-word");
    const std::string line = lineOf(r);
    CHECK_MSG(line.find("\"untraceable\":true") != std::string::npos, "");
    CHECK_MSG(line.find("\"anomaly\":false") != std::string::npos, "");

    r.provenance = attribute(DecoderId::MeshCoreV1, Reason::ReservedValue);
    const std::string bad = lineOf(r);
    CHECK_MSG(bad.find("\"untraceable\":false") != std::string::npos, "");
    CHECK_MSG(bad.find("\"anomaly\":true") != std::string::npos,
              "a reserved value is an anomaly about the air");
  }

  // --- capacity -------------------------------------------------------------------

  {
    Record r = sampleRecord();
    char tiny[32];
    CHECK_MSG(toJsonLine(r, tiny, sizeof(tiny)) == 0,
              "a short buffer is a refusal, not a truncated line: half a JSON object "
              "parses as valid JSON right up until it does not");
  }
}

void suite_wire() {
  harness::suite("Wire");

  {
    std::uint8_t buf[kMaxWireBytes];
    const Record r = sampleRecord();
    const std::size_t n = toWire(r, buf, sizeof(buf));
    CHECK_MSG(n > kWireHeaderBytes, "a frame has a header and a payload");
    CHECK(isWireFrame(buf, n));

    CHECK_EQ(buf[0], kWireMagic0);
    CHECK_EQ(buf[1], kWireMagic1);
    CHECK_EQ(buf[2], kWireMagic2);
    CHECK_EQ(buf[3], kWireMagic3);
    CHECK_EQ(buf[4], kWireVersion);
    CHECK_MSG(buf[5] == kWireHeaderBytes, "the reader is told how long the header is");

    const std::uint16_t total = static_cast<std::uint16_t>(buf[6] |
                                                           (static_cast<std::uint16_t>(buf[7]) << 8));
    CHECK_MSG(static_cast<std::size_t>(total) + 8u == n, "and how long the whole thing is");

    const std::uint8_t flags = buf[8];
    CHECK_MSG((flags & kWireFlagSyncAvailable) != 0, "the sync byte was available");
    CHECK_MSG((flags & kWireFlagCarrierOnly) == 0, "and this verdict was not carrier-only");
    CHECK_EQ(buf[9], static_cast<std::uint8_t>(Protocol::MeshCore));

    // Fingerprint at a fixed offset, little-endian, so a phone can group repeats
    // without decoding anything.
    std::uint64_t fp = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      fp |= static_cast<std::uint64_t>(buf[27 + i]) << (8 * i);
    }
    CHECK_EQ(fp, r.fingerprint);

    // The raw bytes follow the header.
    CHECK_EQ(static_cast<int>(buf[kWireHeaderBytes]), 0x15);

    // The decoded fields are NUL-terminated pairs after the payload. Searched from
    // the payload's end rather than from byte 0: the raw bytes ahead of it are
    // arbitrary and may well contain a NUL, which would end a strstr immediately.
    CHECK_EQ(static_cast<int>(buf[n - 1]), 0);
    const char* strings = reinterpret_cast<const char*>(buf + kWireHeaderBytes + r.length);
    const std::size_t stringsLen = n - (kWireHeaderBytes + r.length);
    CHECK_MSG(containsField(strings, stringsLen, "mc_type"),
              "the field keys are in the frame");
    CHECK_MSG(containsField(strings, stringsLen, "grp_txt"),
              "and so are their values");
    CHECK_MSG(containsField(strings, stringsLen, "hello"), "including the decoded text");
    // Every field is NUL terminated and the list is closed by an empty key, so a
    // reader can walk it without a length per field.
    CHECK_EQ(static_cast<int>(buf[n - 1]), 0);
    CHECK_MSG(strings[stringsLen - 2] == 0x00, "the list ends with an empty key");
  }
  {
    // Corrupt, noise and filtered all survive the trip as bits.
    Record r = sampleRecord();
    r.corrupt = true;
    r.noise = true;
    r.filtered = true;
    r.verdict.carrierOnly = true;
    std::uint8_t buf[kMaxWireBytes];
    const std::size_t n = toWire(r, buf, sizeof(buf));
    CHECK(n > 0);
    const std::uint8_t flags = buf[8];
    CHECK((flags & kWireFlagCorrupt) != 0);
    CHECK((flags & kWireFlagNoise) != 0);
    CHECK((flags & kWireFlagFiltered) != 0);
    CHECK((flags & kWireFlagCarrierOnly) != 0);
  }
  {
    // SNR as tenths of a decibel, so no float crosses a byte-oriented link. And
    // clamped rather than wrapped: a wrapped value reads as a plausible wrong one.
    Record r = sampleRecord();
    std::uint8_t buf[kMaxWireBytes];
    toWire(r, buf, sizeof(buf));
    std::int16_t snr = static_cast<std::int16_t>(buf[23] |
                                                 (static_cast<std::int16_t>(buf[24]) << 8));
    CHECK_EQ(snr, -75);

    r.link.snrDb = 1e9f;
    toWire(r, buf, sizeof(buf));
    snr = static_cast<std::int16_t>(buf[23] | (static_cast<std::int16_t>(buf[24]) << 8));
    CHECK_MSG(snr == 32767, "clamped, not wrapped");

    r.link.snrDb = -1e9f;
    toWire(r, buf, sizeof(buf));
    snr = static_cast<std::int16_t>(buf[23] | (static_cast<std::int16_t>(buf[24]) << 8));
    CHECK_MSG(snr == -32768, "clamped at the bottom too");
  }
  {
    // Framing checks.
    const std::uint8_t junk[64] = {};
    CHECK(!isWireFrame(junk, sizeof(junk)));
    CHECK(!isWireFrame(nullptr, 64));
    std::uint8_t buf[kMaxWireBytes];
    CHECK(toWire(sampleRecord(), buf, sizeof(buf)) > 0);
    CHECK(!isWireFrame(buf, 8));

    // A short buffer is a refusal, not half a record.
    std::uint8_t small[16];
    CHECK_MSG(toWire(sampleRecord(), small, sizeof(small)) == 0,
              "a phone must never be handed half a record to misparse");
  }
  {
    // A future firmware with a longer header is still a frame, and says so: the
    // reader must be able to tell 'newer' from 'not a capture'.
    std::uint8_t buf[kMaxWireBytes];
    const std::size_t n = toWire(sampleRecord(), buf, sizeof(buf));
    std::uint8_t copy[kMaxWireBytes];
    for (std::size_t i = 0; i < n; ++i) copy[i] = buf[i];
    copy[5] = static_cast<std::uint8_t>(kWireHeaderBytes + 8);
    CHECK_MSG(isWireFrame(copy, n), "a longer header is a newer frame, not a bad one");
    copy[4] = 99;
    CHECK_MSG(!isWireFrame(copy, n), "but an unknown version is refused");
  }
}

void suite_counters() {
  harness::suite("Counters");

  {
    Counters c;
    CHECK_EQ(c.total, 0u);
    CHECK_EQ(c.analysed(), 0u);
    CHECK_MSG(c.untraceableRatio() == 0.0f,
              "no frames means no ratio, not zero percent unattributable");
  }
  {
    // Noise is counted and excluded from every knowledge total. Otherwise "we heard
    // 400 MeshCore frames" means something entirely different from what it appears
    // to mean.
    Counters c;
    Record noise;
    noise.noise = true;
    c.observe(noise);
    CHECK_EQ(c.total, 1u);
    CHECK_EQ(c.noise, 1u);
    CHECK_EQ(c.analysed(), 0u);
    CHECK_EQ(c.byProtocol[static_cast<std::size_t>(Protocol::MeshCore)], 0u);

    Record good;
    good.protocol = Protocol::MeshCore;
    good.provenance = attribute(DecoderId::MeshCoreV1, Reason::FullyDecoded);
    good.verdict.network = Network::MeshCoreEu868;
    c.observe(good);

    CHECK_EQ(c.total, 2u);
    CHECK_EQ(c.noise, 1u);
    CHECK_EQ(c.analysed(), 1u);
    CHECK_EQ(c.byProtocol[static_cast<std::size_t>(Protocol::MeshCore)], 1u);
    CHECK_EQ(c.byAttribution[static_cast<std::size_t>(Attribution::Attributed)], 1u);
    CHECK_EQ(c.untraceable, 0u);
    CHECK(c.untraceableRatio() == 0.0f);
  }
  {
    // The headline ratio, which is the number the whole triage design turns on.
    Counters c;
    for (int i = 0; i < 7; ++i) {
      Record r;
      r.provenance = attribute(DecoderId::None, Reason::ForeignSyncWord);
      c.observe(r);
    }
    for (int i = 0; i < 3; ++i) {
      Record r;
      r.provenance = attribute(DecoderId::MeshCoreV1, Reason::FullyDecoded);
      c.observe(r);
    }
    CHECK_EQ(c.total, 10u);
    CHECK_EQ(c.untraceable, 7u);
    CHECK_MSG(std::abs(c.untraceableRatio() - 0.7f) < 0.001f, "7 of 10");
    CHECK_EQ(c.byReason[static_cast<std::size_t>(Reason::ForeignSyncWord)], 7u);
    CHECK_EQ(c.reasonCount(Reason::FullyDecoded), 3u);
  }
  {
    // Filtered-out frames are counted in their own total, so "1000 frames and 4
    // records" is answerable without going back to the firmware.
    Counters c;
    for (int i = 0; i < 4; ++i) {
      Record r;
      r.filtered = true;
      c.observe(r);
    }
    for (int i = 0; i < 2; ++i) {
      Record r;
      r.filtered = false;
      c.observe(r);
    }
    CHECK_EQ(c.passed, 2u);
    CHECK_EQ(c.rejected, 4u);
    CHECK_EQ(c.total, 6u);
  }
  {
    // Corrupt frames are counted and attributed to no protocol.
    Counters c;
    Record r;
    r.corrupt = true;
    c.observe(r);
    CHECK_EQ(c.corrupt, 1u);
    CHECK_EQ(c.analysed(), 1u);
  }
  {
    // Carrier-only and corroborated.
    //
    // `PlanVerdict::carrierOnly` defaults to true -- "this verdict rests on nothing
    // but the carrier" is the honest state of a verdict nobody has improved on -- so
    // the second record has to opt *out* explicitly or it is counted too.
    Counters c;
    Record a;
    a.verdict.carrierOnly = true;
    c.observe(a);
    Record b;
    b.verdict.carrierOnly = false;
    b.verdict.confidence = Confidence::CarrierSyncAndBody;
    b.provenance.claimants = 2;
    c.observe(b);
    CHECK_EQ(c.carrierOnly, 1u);
    CHECK_EQ(c.corroborated, 1u);
  }
  {
    // The rate window, across a millis() wrap. A device left running for 49 days
    // hits that, and it is not a theoretical concern for a tool whose selling point
    // is being left running.
    Counters c;
    c.windowStartMs = 0;
    for (int i = 0; i < 10; ++i) c.observe(Record{});
    c.rollWindow(1000);
    CHECK_MSG(c.framesPerMinute == 0.0f, "the window has not elapsed yet");

    c.rollWindow(kRateWindowMs);
    CHECK_MSG(c.framesPerMinute > 59.0f && c.framesPerMinute < 61.0f,
              "10 frames in a 10s window is 60 per minute");
    CHECK_EQ(c.windowFrames, 0u);

    // The wrap itself. Unsigned arithmetic, so elapsed is computed modulo 2^32:
    // 0xFFFFF000 is 4096 below the top of the range, so twenty seconds later is
    // 0xFFFFF000 + 20000 = 0x100003D20, which wraps to 0x3D20. Five frames in twenty
    // seconds is fifteen per minute -- which is the whole point of the check, because
    // signed arithmetic here would have produced a negative interval and a rate of
    // roughly minus seven.
    Counters w;
    w.windowStartMs = 0xFFFFF000u;
    for (int i = 0; i < 5; ++i) w.observe(Record{});
    w.rollWindow(0x00003D20u);
    CHECK_MSG(w.framesPerMinute > 14.0f && w.framesPerMinute < 16.0f,
              "the wrap is handled and the rate is still right");
    CHECK_MSG(w.windowStartMs == 0x00003D20u, "and the window restarted from the new now");
  }
  {
    const std::string s = renderCounters([] {
      Counters c;
      Record r;
      r.provenance = attribute(DecoderId::None, Reason::NoEvidenceAtAll);
      c.observe(r);
      Record g;
      g.verdict.carrierOnly = true;
      c.observe(g);
      return c;
    }());
    CHECK_MSG(s.find("frames") != std::string::npos, "");
    CHECK_MSG(s.find("untraceable") != std::string::npos, "the headline ratio is in the summary");
    CHECK_MSG(s.find("no-evidence-at-all") != std::string::npos,
              "the reason table is the point of the module and is printed in full");
    CHECK_MSG(s.find("promiscuous") != std::string::npos,
              "a high carrier-only count tells the operator their radio is misconfigured, "
              "and says how to fix it");
  }
}
