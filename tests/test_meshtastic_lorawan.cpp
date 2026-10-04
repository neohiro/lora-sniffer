// SPDX-License-Identifier: MIT
//
// Meshtastic and LoRaWAN: the two formats where the security model puts
// something readable in the clear.
//
// Meshtastic's 16-byte header is plaintext, so an unkeyed sniffer can still name
// the sender, the packet id, the hop limit and the channel hash. That is the
// whole reason this file has any tests at all: it is the difference between
// "unknown frame" and "a node is talking and here is which channel it is on".
//
// The protobuf reader is exercised here too, since a bounds bug in it would
// present as confidently wrong field values rather than as a crash -- which is
// the failure mode that matters for a logging tool.

#include <cstring>
#include <vector>

#include "harness.hpp"
#include "sniffer/LoRaWanFrame.hpp"
#include "sniffer/MeshtasticFrame.hpp"
#include "sniffer/Proto.hpp"

using namespace sniff;
using namespace sniff::meshtastic;
using namespace sniff::lorawan;

namespace {

// A Meshtastic header with the three magic bytes and the documented layout.
std::vector<std::uint8_t> mtFrame(std::uint32_t from, std::uint32_t id,
                                  std::uint8_t channelHash, std::uint8_t hopStart,
                                  std::uint8_t hopLimit, bool wantAck,
                                  const std::vector<std::uint8_t>& body,
                                  bool viaMqtt = false) {
  std::vector<std::uint8_t> v;
  v.push_back(kMagic0);
  v.push_back(kMagic1);
  v.push_back(kMagic2);
  v.push_back(0xFF);  // to, low byte
  v.push_back(static_cast<std::uint8_t>(from & 0xFF));
  v.push_back(static_cast<std::uint8_t>((from >> 8) & 0xFF));
  v.push_back(static_cast<std::uint8_t>((from >> 16) & 0xFF));
  v.push_back(static_cast<std::uint8_t>((from >> 24) & 0xFF));
  v.push_back(static_cast<std::uint8_t>(id & 0xFF));
  v.push_back(static_cast<std::uint8_t>((id >> 8) & 0xFF));
  v.push_back(static_cast<std::uint8_t>((id >> 16) & 0xFF));
  v.push_back(static_cast<std::uint8_t>((id >> 24) & 0xFF));
  const std::uint8_t flags =
      static_cast<std::uint8_t>((hopLimit & 0x07) | (wantAck ? 0x08 : 0x00) |
                                (viaMqtt ? 0x10 : 0x00) | ((hopStart & 0x07) << 5));
  v.push_back(flags);
  v.push_back(channelHash);
  v.push_back(0x00);  // next hop
  v.push_back(0x00);  // relay node
  v.insert(v.end(), body.begin(), body.end());
  return v;
}

// Protobuf writer, only as much as the tests need.
void putVarint(std::vector<std::uint8_t>& v, std::uint64_t x) {
  do {
    std::uint8_t b = static_cast<std::uint8_t>(x & 0x7Fu);
    x >>= 7;
    if (x != 0) b |= 0x80u;
    v.push_back(b);
  } while (x != 0);
}

void putTag(std::vector<std::uint8_t>& v, std::uint32_t field, proto::WireType wire) {
  putVarint(v, (static_cast<std::uint64_t>(field) << 3) | static_cast<std::uint64_t>(wire));
}

void putFixed32(std::vector<std::uint8_t>& v, std::uint32_t field, std::uint32_t x) {
  putTag(v, field, proto::WireType::Fixed32);
  for (int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
}

void putVarintField(std::vector<std::uint8_t>& v, std::uint32_t field, std::uint64_t x) {
  putTag(v, field, proto::WireType::Varint);
  putVarint(v, x);
}

void putBytes(std::vector<std::uint8_t>& v, std::uint32_t field, const std::vector<std::uint8_t>& b) {
  putTag(v, field, proto::WireType::LengthDelimited);
  putVarint(v, b.size());
  v.insert(v.end(), b.begin(), b.end());
}

}  // namespace

void suite_meshtastic_frame() {
  harness::suite("MeshtasticFrame");

  // --- magic ---------------------------------------------------------------

  {
    const std::uint8_t good[] = {kMagic0, kMagic1, kMagic2, 0x00};
    CHECK(hasMagic(good, sizeof(good)));
    const std::uint8_t near[] = {kMagic0, kMagic1, 0x17, 0x00};
    CHECK(!hasMagic(near, sizeof(near)));
    const std::uint8_t shortf[] = {kMagic0, kMagic1};
    CHECK(!hasMagic(shortf, sizeof(shortf)));
    CHECK(!hasMagic(nullptr, 10));
  }

  // --- header fields -------------------------------------------------------

  {
    const std::vector<std::uint8_t> body = {0x08, 0x01, 0x10, 0x21};
    const std::vector<std::uint8_t> f = mtFrame(0x1A2B3C4D, 0x0000BEEF, 0x8F, 7, 3, true, body);
    const Header h = meshtastic::parse(f.data(), f.size());
    REQUIRE(h.wellFormed);
    CHECK_EQ(h.from, 0x1A2B3C4Du);
    CHECK_EQ(h.packetId, 0x0000BEEFu);
    CHECK_EQ(h.channelHash, 0x8F);
    CHECK_EQ(h.hopStart, 7);
    CHECK_EQ(h.hopLimit, 3);
    CHECK(h.wantAck);
    CHECK(!h.viaMqtt);
    CHECK_EQ(h.payloadOffset, kHeaderBytes);
    CHECK_EQ(h.payloadLength, body.size());

    CHECK(nodeIdText(0x1A2B3C4D) == "!1a2b3c4d");
    const std::string d = describe(h, Decoded{});
    CHECK_MSG(d.find("from=!1a2b3c4d") != std::string::npos, "node ids use the !deadbeef form");
    CHECK(d.find("hops=7/3") != std::string::npos);
    CHECK(d.find("wantack") != std::string::npos);
  }

  // --- flag bit positions --------------------------------------------------

  {
    // Each flag isolated, so a mis-shifted mask is caught rather than a
    // combination that happens to work.
    const std::vector<std::uint8_t> body = {0x01};
    const std::vector<std::uint8_t> ack = mtFrame(1, 1, 0, 0, 0, true, body);
    Header h = meshtastic::parse(ack.data(), ack.size());
    CHECK(h.wellFormed && h.wantAck && !h.viaMqtt && h.hopLimit == 0);

    const std::vector<std::uint8_t> mqtt = mtFrame(1, 1, 0, 0, 0, false, body, /*viaMqtt=*/true);
    h = meshtastic::parse(mqtt.data(), mqtt.size());
    CHECK(h.wellFormed && !h.wantAck && h.viaMqtt);

    const std::vector<std::uint8_t> hops = mtFrame(1, 1, 0, 4, 2, false, body);
    h = meshtastic::parse(hops.data(), hops.size());
    CHECK(h.wellFormed && h.hopStart == 4 && h.hopLimit == 2 && !h.wantAck && !h.viaMqtt);
  }

  // --- truncation ----------------------------------------------------------

  {
    // Magic present, header incomplete.
    const std::uint8_t f[] = {kMagic0, kMagic1, kMagic2, 0xFF, 0x01, 0x02};
    const Header h = meshtastic::parse(f, sizeof(f));
    CHECK(!h.wellFormed);
    CHECK(h.problem == Reason::Truncated);
    CHECK_MSG(h.provenance.decoder == DecoderId::MeshtasticHeader,
              "even a truncated header is identified as Meshtastic: the magic is unambiguous");
  }
  {
    // Header complete, no body. Counting this as a decoded frame would overstate
    // what was learned.
    const std::vector<std::uint8_t> f = mtFrame(1, 1, 0, 0, 0, false, {});
    const Header h = meshtastic::parse(f.data(), f.size());
    CHECK(!h.wellFormed);
    CHECK(h.problem == Reason::Truncated);
  }
  {
    const std::uint8_t none[] = {0x01, 0x02, 0x03};
    const Header h = meshtastic::parse(none, sizeof(none));
    CHECK(!h.wellFormed);
    CHECK(h.problem == Reason::NoEvidenceAtAll);
    CHECK(h.provenance.decoder == DecoderId::None);
  }

  // --- the encrypted marker ------------------------------------------------
  //
  // 0x01 leads a Meshtastic ciphertext body. Observing it is a strong hint and
  // not proof, which is why the outcome is `encrypted-no-key` and not a walk of
  // the bytes as protobuf.

  {
    const std::vector<std::uint8_t> body = {0x01, 0x01, 0x4D, 0x3C, 0x2B, 0x1A, 0x00};
    const std::vector<std::uint8_t> f = mtFrame(0x1A2B3C4D, 7, 0x42, 3, 3, false, body);
    const Header h = meshtastic::parse(f.data(), f.size());
    REQUIRE(h.wellFormed);
    CHECK_MSG(h.channelHash != kPrimaryChannelHash, "a non-primary channel is what we expect");
    const Data d = parseData(f.data() + h.payloadOffset, h.payloadLength);
    CHECK(!d.present);
    CHECK(d.problem == Reason::EncryptedNoKey);
  }

  // --- plaintext Data ------------------------------------------------------

  {
    std::vector<std::uint8_t> data;
    putFixed32(data, 1, 0x1A2B3C4D);  // from
    putFixed32(data, 2, 0xFFFFFFFFu); // to, broadcast
    putVarintField(data, 3, 0);        // channel

    const std::vector<std::uint8_t> f = mtFrame(0x1A2B3C4D, 7, kPrimaryChannelHash, 3, 3, false,
                                                data);
    const Header h = meshtastic::parse(f.data(), f.size());
    REQUIRE(h.wellFormed);
    const Data d = parseData(f.data() + h.payloadOffset, h.payloadLength);
    REQUIRE(d.present);
    CHECK(d.problem == Reason::FullyDecoded);
    CHECK_EQ(d.from, 0x1A2B3C4Du);
    CHECK_EQ(d.to, 0xFFFFFFFFu);
  }
  {
    // The real prize: a plaintext TEXT_MESSAGE_APP read with no key at all.
    std::vector<std::uint8_t> app;
    putVarintField(app, 1, 1);  // portnum = TEXT_MESSAGE_APP

    std::vector<std::uint8_t> text;
    putBytes(text, 1, [] { return std::vector<std::uint8_t>{'h', 'i', ' ', 't', 'h', 'e', 'r', 'e'}; }());

    putTag(app, 2, proto::WireType::LengthDelimited);
    putVarint(app, text.size());
    app.insert(app.end(), text.begin(), text.end());

    std::vector<std::uint8_t> data;
    putFixed32(data, 1, 0x1A2B3C4D);
    putBytes(data, 4, app);  // Data.payload

    const std::vector<std::uint8_t> f =
        mtFrame(0x1A2B3C4D, 7, kPrimaryChannelHash, 3, 3, false, data);
    const Header h = meshtastic::parse(f.data(), f.size());
    REQUIRE(h.wellFormed);
    const Data d = parseData(f.data() + h.payloadOffset, h.payloadLength);
    REQUIRE(d.present);
    REQUIRE(d.havePayload);

    const Decoded dec = decodePlaintext(d);
    CHECK_MSG(dec.ok, "a portnum must be found in a plaintext payload");
    CHECK_EQ(dec.portnum, 1u);
    CHECK(std::strcmp(dec.portNumLabel, "TEXT_MESSAGE_APP") == 0);
  }

  // --- portnum names -------------------------------------------------------

  CHECK(std::strcmp(portNumName(1), "TEXT_MESSAGE_APP") == 0);
  CHECK(std::strcmp(portNumName(3), "POSITION_APP") == 0);
  CHECK(std::strcmp(portNumName(67), "TRACEROUTE_APP") == 0);
  CHECK_MSG(portNumName(4242)[0] == '\0',
            "an unlisted portnum returns no name rather than a wrong one");

  // --- the protobuf reader, which is where a bounds bug would hide ----------

  {
    // A varint that runs past the end must fail, not read whatever follows.
    const std::uint8_t overrun[] = {0xFF, 0xFF, 0xFF, 0xFF};
    proto::Reader r(overrun, sizeof(overrun));
    std::uint64_t v = 0;
    CHECK(!r.varint(&v));
  }
  {
    // A length prefix larger than the buffer.
    const std::uint8_t bad[] = {0x0A, 0x7F};
    proto::Reader r(bad, sizeof(bad));
    const std::uint8_t* p = nullptr;
    std::size_t n = 0;
    CHECK(!r.bytes(&p, &n));
  }
  {
    // fixed32 with three bytes available.
    const std::uint8_t bad[] = {0x0D, 0x01, 0x02, 0x03};
    proto::Reader r(bad, sizeof(bad));
    proto::Tag t;
    REQUIRE(r.next(&t));
    CHECK(t.field == 1 && t.wire == proto::WireType::Fixed32);
    std::uint32_t v = 0;
    CHECK(!r.fixed32(&v));
  }
  {
    // Field number 0 is illegal on the wire and must be rejected.
    const std::uint8_t bad[] = {0x00};
    proto::Reader r(bad, sizeof(bad));
    proto::Tag t;
    CHECK(!r.next(&t));
  }
  {
    // A group marker is deprecated and nothing legitimate emits one.
    const std::uint8_t bad[] = {0x0B};
    proto::Reader r(bad, sizeof(bad));
    proto::Tag t;
    CHECK(!r.next(&t));
  }
  {
    // A well-formed sequence with an unknown field in the middle: the unknown
    // field must be skipped and the known one after it still found.
    std::vector<std::uint8_t> seq;
    putFixed32(seq, 1, 0xDEADBEEF);
    putBytes(seq, 77, std::vector<std::uint8_t>{1, 2, 3, 4, 5});
    putFixed32(seq, 2, 0x12345678);

    const Data d = parseData(seq.data(), seq.size());
    REQUIRE(d.present);
    CHECK_EQ(d.from, 0xDEADBEEFu);
    CHECK_MSG(d.to == 0x12345678u, "an unknown field must not desynchronise the reader");
  }
  {
    // Body that is structured protobuf but contains none of the fields we know.
    // That is AnonymousButStructured, not a clean "no data".
    std::vector<std::uint8_t> seq;
    putBytes(seq, 99, std::vector<std::uint8_t>{0xAA, 0xBB});
    const Data d = parseData(seq.data(), seq.size());
    CHECK(!d.present);
    CHECK(d.problem == Reason::AnonymousButStructured);
  }
}

void suite_lorawan_frame() {
  harness::suite("LoRaWanFrame");

  // --- names ---------------------------------------------------------------

  CHECK(std::strcmp(mTypeName(MType::JoinRequest), "join-request") == 0);
  CHECK(std::strcmp(mTypeName(MType::UnconfirmedDataUp), "data-up-unconfirmed") == 0);
  CHECK(std::strcmp(className(Class::C), "C") == 0);

  // --- JoinRequest: the payload that makes a frequency survey possible ------

  {
    std::uint8_t f[23];
    f[0] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(MType::JoinRequest) << 5);  // major 0
    // AppEUI then DevEUI, least significant byte first on the wire.
    for (int i = 0; i < 8; ++i) {
      f[1 + i] = static_cast<std::uint8_t>(0xA0 + i);
      f[9 + i] = static_cast<std::uint8_t>(0x10 + i);
    }
    f[17] = 0x34;
    f[18] = 0x12;
    for (int i = 19; i < 23; ++i) f[i] = 0xEE;  // MIC

    const Frame p = lorawan::parse(f, sizeof(f));
    REQUIRE(p.wellFormed);
    CHECK(p.majorValid);
    CHECK(p.mType == MType::JoinRequest);
    CHECK_EQ(p.devNonce, 0x1234);
    CHECK_EQ(p.micLength, 4u);

    const std::string d = describe(p);
    CHECK_MSG(d.find("join-request") != std::string::npos, "");
    CHECK_MSG(d.find("deveui=17:16:15:14:13:12:11:10") != std::string::npos,
              "an EUI is printed most-significant byte first, the way tools print them");
    CHECK_MSG(d.find("infrastructure, not a mesh node") != std::string::npos,
              "the note that this is somebody's infrastructure belongs in the summary");
  }

  // --- data up -------------------------------------------------------------

  {
    std::uint8_t f[20] = {};
    f[0] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(MType::UnconfirmedDataUp) << 5);
    f[1] = 0xEF;
    f[2] = 0xBE;
    f[3] = 0xAD;
    f[4] = 0xDE;  // DevAddr, little-endian
    f[5] = 0x80;  // FCtrl: ADR set
    f[6] = 0x07;
    f[7] = 0x00;  // FCnt = 7, little-endian
    f[8] = 0x01;  // FPort
    for (int i = 9; i < 16; ++i) f[i] = static_cast<std::uint8_t>(i);
    for (int i = 16; i < 20; ++i) f[i] = 0x5A;  // MIC

    const Frame p = lorawan::parse(f, sizeof(f));
    REQUIRE(p.wellFormed);
    CHECK(p.adr);
    CHECK(!p.ack);
    CHECK(p.downlinkClass == Class::A);
    CHECK_EQ(p.fCnt, 7);
    CHECK_EQ(p.fPort, 1);
    CHECK_EQ(p.devAddr, 0xDEADBEEFu);
    CHECK_EQ(p.payloadLength, 7u);
    CHECK_EQ(p.micOffset, 16u);
    CHECK(describe(p).find("adr") != std::string::npos);
  }

  // --- truncation and reserved majors --------------------------------------

  {
    const Frame p = lorawan::parse(nullptr, 0);
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::NoiseOrTooShort);

    const std::uint8_t shortf[] = {0x40, 0x00};
    const Frame q = lorawan::parse(shortf, sizeof(shortf));
    CHECK(!q.wellFormed);
    CHECK(q.problem == Reason::Truncated);

    // Major version 3 does not exist. Reading its layout on a guess is exactly
    // what this decoder refuses to do.
    std::uint8_t badMajor[20] = {};
    badMajor[0] = static_cast<std::uint8_t>((static_cast<std::uint8_t>(MType::UnconfirmedDataUp) << 5) | (3 << 1));
    const Frame r = lorawan::parse(badMajor, sizeof(badMajor));
    CHECK(!r.wellFormed);
    CHECK_MSG(r.problem == Reason::ReservedValue, "major 3 is not a version this decoder knows");
    CHECK(!r.majorValid);
  }
  {
    // Long enough for a header but not for the MIC.
    std::uint8_t f[10] = {};
    f[0] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(MType::UnconfirmedDataUp) << 5);
    const Frame p = lorawan::parse(f, sizeof(f));
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::Truncated);
  }
  {
    // A join request must be at least 23 bytes.
    std::uint8_t f[10] = {};
    f[0] = static_cast<std::uint8_t>(static_cast<std::uint8_t>(MType::JoinRequest) << 5);
    const Frame p = lorawan::parse(f, sizeof(f));
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::Truncated);
  }

  // --- every MType round-trips ---------------------------------------------

  for (std::uint8_t i = 0; i <= 7; ++i) {
    const MType t = static_cast<MType>(i);
    CHECK_MSG(mTypeName(t)[0] != '\0', "every MType needs a name");
    CHECK_MSG(std::strcmp(mTypeName(t), "invalid") != 0, "every MType is defined");
  }
}
