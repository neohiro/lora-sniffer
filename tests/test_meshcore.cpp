// SPDX-License-Identifier: MIT
//
// The MeshCore v1 packet format, and the payload classes that are plaintext.
//
// Every byte sequence here is built from the specification rather than from a
// real capture, which is deliberate: it means the suite pins *what the format is*
// rather than *what one device happened to send*. The field most likely to be
// got wrong by anyone implementing this from memory is the packed path-length
// byte, so it gets the most attention here.

#include <cstring>
#include <vector>

#include "harness.hpp"
#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/MeshCorePayload.hpp"

using namespace sniff;
using namespace sniff::meshcore;

namespace {

// header = 0bVVPPPPRR
std::uint8_t hdr(PayloadType type, RouteType route, PayloadVersion v) {
  return static_cast<std::uint8_t>((static_cast<unsigned>(v) << 6) |
                                   (static_cast<unsigned>(type) << 2) |
                                   static_cast<unsigned>(route));
}

// A minimal, well-formed ADVERT: public key, timestamp, signature, then appdata
// with flags and a name.
std::vector<std::uint8_t> advertBytes(const char* name, std::uint8_t flags) {
  std::vector<std::uint8_t> v;
  for (int i = 0; i < 32; ++i) v.push_back(static_cast<std::uint8_t>(i + 1));
  v.push_back(0x10);
  v.push_back(0x00);
  v.push_back(0x00);
  v.push_back(0x00);  // timestamp
  for (int i = 0; i < 64; ++i) v.push_back(0xAB);  // signature
  v.push_back(flags);
  for (const char* p = name; *p != '\0'; ++p) v.push_back(static_cast<std::uint8_t>(*p));
  return v;
}

}  // namespace

void suite_meshcore_frame() {
  harness::suite("MeshCoreFrame");

  // --- header decomposition ------------------------------------------------

  {
    RouteType r;
    PayloadType p;
    PayloadVersion v;
    REQUIRE(readHeader(hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1), &r, &p,
                       &v));
    CHECK(r == RouteType::Flood);
    CHECK(p == PayloadType::GrpTxt);
    CHECK(v == PayloadVersion::V1);
  }
  {
    // All four route types, both bits.
    RouteType r;
    PayloadType p;
    PayloadVersion v;
    CHECK(readHeader(0x0F, &r, &p, &v) && r == RouteType::TransportDirect);
    CHECK_MSG(readHeader(0x00, &r, &p, &v) && r == RouteType::TransportFlood, "route type 00 is transport-flood");
    CHECK_MSG(readHeader(0x03, &r, &p, &v) && r == RouteType::TransportDirect,
              "route type 11 is transport-direct -- both transport codes are present");
    CHECK(readHeader(0x02, &r, &p, &v) && r == RouteType::Direct);
    CHECK(readHeader(0x01, &r, &p, &v) && r == RouteType::Flood);
  }

  // --- name coverage -------------------------------------------------------

  CHECK(std::strcmp(payloadTypeName(PayloadType::GrpTxt), "grp_txt") == 0);
  CHECK(std::strcmp(payloadTypeName(PayloadType::RawCustom), "raw_custom") == 0);
  CHECK(std::strcmp(routeTypeName(RouteType::TransportFlood), "transport_flood") == 0);
  CHECK(std::strcmp(payloadVersionName(PayloadVersion::Reserved3), "reserved_v3") == 0);

  CHECK(payloadTypeDefined(PayloadType::Req));
  CHECK(payloadTypeDefined(PayloadType::RawCustom));
  CHECK_MSG(!payloadTypeDefined(PayloadType::Reserved0C), "0x0C is reserved");
  CHECK(!payloadTypeDefined(PayloadType::Reserved0D));
  CHECK(!payloadTypeDefined(PayloadType::Reserved0E));

  {
    // Every enumerator must have a distinct name.
    for (std::uint8_t i = 0; i <= 0x0F; ++i) {
      for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j <= 0x0F; ++j) {
        CHECK(std::strcmp(payloadTypeName(static_cast<PayloadType>(i)),
                          payloadTypeName(static_cast<PayloadType>(j))) != 0);
      }
    }
  }

  // --- the packed path-length byte ----------------------------------------
  //
  // This is the field people get wrong. It is NOT a byte count.

  {
    // 0x05 = five hops of 1-byte hashes -> five path bytes.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x05, 1, 2, 3, 4, 5, 0xAA, 0xBB};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    REQUIRE(p.wellFormed);
    CHECK_EQ(p.hopCount, 5);
    CHECK_EQ(p.hashSize, 1);
    CHECK_EQ(p.pathBytes, 5);
    CHECK_EQ(p.payloadOffset, 7);
    CHECK_EQ(p.payloadLength, 2);
  }
  {
    // 0x45 = five hops of 2-byte hashes -> TEN path bytes. Reading this as "5
    // bytes" would put four path bytes in the payload.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xAA, 0xBB};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    REQUIRE(p.wellFormed);
    CHECK_EQ(p.hopCount, 5);
    CHECK_EQ(p.hashSize, 2);
    CHECK_EQ(p.pathBytes, 10);
    CHECK_EQ(p.payloadOffset, 12);
    CHECK_EQ(p.payloadLength, 2);
  }
  {
    // 0x8A = ten hops of 3-byte hashes -> 30 bytes, so the frame has to actually
    // contain them. The earlier version of this case supplied only the header byte
    // and the parser correctly refused it, which is the parser working.
    std::vector<std::uint8_t> frame;
    frame.push_back(hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1));
    frame.push_back(0x8A);
    for (int i = 0; i < 30; ++i) frame.push_back(static_cast<std::uint8_t>(i));
    frame.push_back(0xAA);

    const Packet p = parse(frame.data(), frame.size(), kMeshCoreSync, true);
    REQUIRE(p.wellFormed);
    CHECK_EQ(p.hopCount, 10);
    CHECK_EQ(p.hashSize, 3);
    CHECK_EQ(p.pathBytes, 30);
    CHECK_EQ(p.payloadLength, 1);

    // The same frame with its path removed is truncated, not silently shortened.
    frame.erase(frame.begin() + 2, frame.end() - 1);
    const Packet q = parse(frame.data(), frame.size(), kMeshCoreSync, true);
    CHECK(!q.wellFormed);
    CHECK_MSG(q.problem == Reason::Truncated, "thirty declared path bytes must all be present");
  }
  {
    // Zero hops, zero path bytes: the common case for a frame emitted next to the
    // sniffer.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x00, 0x01, 0x8F, 'h', 'i'};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    REQUIRE(p.wellFormed);
    CHECK_EQ(p.hopCount, 0);
    CHECK_EQ(p.pathBytes, 0);
    CHECK_EQ(p.payloadOffset, 2);
    CHECK_MSG(p.payloadLength == 4, "everything after the zero-length path is payload");
  }

  // --- the reserved hash size code ----------------------------------------
  //
  // 0b11 in bits 6-7 is reserved, NOT four-byte hashes. Treating it as four
  // would let a corrupt frame sail through with a plausible path length.

  {
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0xC5, 1, 2, 3, 4, 5, 0xAA};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK_MSG(!p.wellFormed, "hash size code 0b11 is reserved and must be refused");
    CHECK(p.hashSizeReserved);
    CHECK(p.problem == Reason::ReservedValue);
    CHECK(p.provenance.attribution == Attribution::Partial);
  }

  // --- transport codes -----------------------------------------------------

  {
    // Route type 0 carries four extra bytes before the path length.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::TransportFlood,
                                      PayloadVersion::V1),
                                  0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x01, 0x02};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    REQUIRE(p.wellFormed);
    CHECK(p.hasTransportCodes);
    CHECK_EQ(p.transportCode1, 0xBBAA);
    CHECK_EQ(p.transportCode2, 0xDDCC);
    CHECK_EQ(p.payloadOffset, 6);
    CHECK_EQ(p.payloadLength, 2);
  }
  {
    // A transport frame whose four bytes are not all there.
    const std::uint8_t frame[] = {
        hdr(PayloadType::GrpTxt, RouteType::TransportFlood, PayloadVersion::V1), 0xAA, 0xBB};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::Truncated);
  }

  // --- truncation and reserved versions ------------------------------------

  {
    const Packet p = parse(nullptr, 0, kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK_MSG(p.problem == Reason::NoiseOrTooShort, "no bytes at all is the shortest case");

    const Packet q = parse(nullptr, 5, kMeshCoreSync, true);
    CHECK(!q.wellFormed);
  }
  {
    // Frame ends before its own declared path.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x45, 1, 2};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK_MSG(p.problem == Reason::Truncated, "five 2-byte hops need ten bytes and only two remain");
  }
  {
    // Path-length byte itself missing.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1)};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::Truncated);
  }
  {
    // A reserved payload version means a format this decoder was not written
    // against. Reading the rest would be inventing structure.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::Reserved2),
                                  0x00, 0x01};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK_MSG(p.provenance.decoder == DecoderId::MeshCoreV1,
              "the decoder still claims it: somebody is running a newer MeshCore");
    CHECK(p.problem == Reason::ReservedValue);
  }
  {
    // Header present, path zero, but no payload at all.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x00};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    CHECK(!p.wellFormed);
    CHECK(p.problem == Reason::Truncated);
  }

  // --- the sync-word contradiction -----------------------------------------

  {
    // Well-formed MeshCore geometry arriving on somebody else's sync byte. That
    // is the interesting case: the body parses, the preamble disagrees, and the
    // operator needs to be told rather than shown a clean MeshCore frame.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x00, 0x01, 0x8F, 'h'};
    const Packet p = parse(frame, sizeof(frame), kMeshtasticPublicSync, true);
    REQUIRE(p.wellFormed);
    CHECK_MSG(p.problem == Reason::KnownSyncUnknownBody,
              "MeshCore geometry on a Meshtastic sync word must be flagged");
    CHECK_MSG(p.provenance.attribution == Attribution::Unattributed,
              "and unattributable, not partial: a decoder claimed the geometry, but the "
              "preamble says the bytes may not even be MeshCore");
  }
  {
    // No sync byte available: a private channel may derive a different one, so the
    // parse stands and no contradiction is claimed.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x00, 0x01, 0x8F, 'h'};
    const Packet p = parse(frame, sizeof(frame), 0x00, false);
    REQUIRE(p.wellFormed);
    CHECK(p.problem == Reason::FullyDecoded);
  }
  {
    // The wildcard 0x00 delivered as a real byte is the same as no byte at all,
    // and must not be treated as a contradicting sync word.
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x00, 0x01, 0x8F, 'h'};
    const Packet p = parse(frame, sizeof(frame), 0x00, true);
    REQUIRE(p.wellFormed);
    CHECK_MSG(p.problem == Reason::FullyDecoded,
              "a wildcard sync byte carries no information and cannot contradict anything");
  }

  // --- describe ------------------------------------------------------------

  {
    const std::uint8_t frame[] = {hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1),
                                  0x45, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0x01, 0x8F, 'h'};
    const Packet p = parse(frame, sizeof(frame), kMeshCoreSync, true);
    const std::string d = describe(p);
    CHECK(d.find("MC grp_txt flood v1") != std::string::npos);
    CHECK(d.find("hops=5") != std::string::npos);
    CHECK(d.find("hash=2B") != std::string::npos);
  }
}

void suite_meshcore_payload() {
  harness::suite("MeshCorePayload");

  // --- ADVERT, the frame that makes a sniffer useful on a keyless channel ---

  {
    // Flags 0x02 = repeater, 0x80 = has name.
    const std::vector<std::uint8_t> body = advertBytes("mast-7", 0x02 | 0x80);

    // header, zero-length path, then the advert body.
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::Advert, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    full.insert(full.end(), body.begin(), body.end());

    const Packet pkt2 = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt2.wellFormed);

    const Payload d = decodePayload(pkt2, full.data(), true);
    REQUIRE(d.ok);
    CHECK(d.decoder == DecoderId::MeshCoreAdvert);
    CHECK(d.hasPublicKey);
    CHECK(std::strcmp(d.text, "mast-7") == 0);
    CHECK(d.roleRepeater);
    CHECK_MSG(std::strcmp(advertRoleName(d), "repeater") == 0, "the role is named");
    CHECK(!d.hasLocation);
    CHECK(d.describe().find("key=01020304") != std::string::npos);
    CHECK(d.describe().find("role=repeater") != std::string::npos);
    CHECK(d.describe().find("name=mast-7") != std::string::npos);
  }
  {
    // Location present: lat/lon as microdegrees.
    std::vector<std::uint8_t> body;
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<std::uint8_t>(i));
    for (int i = 0; i < 4; ++i) body.push_back(0);  // timestamp
    for (int i = 0; i < 64; ++i) body.push_back(0);  // signature
    body.push_back(0x10);                             // has location
    // Chosen so the expected value is exactly checkable by hand rather than by the
    // same arithmetic the decoder uses: 50000 microdegrees = 0x0000C350, and
    // -120000 microdegrees = 0xFFFE2B40 as a two's-complement 32-bit integer. Both
    // little-endian, which is what the format specifies.
    const std::uint8_t lat[] = {0x50, 0xC3, 0x00, 0x00};
    const std::uint8_t lon[] = {0x40, 0x2B, 0xFE, 0xFF};
    for (std::uint8_t b : lat) body.push_back(b);
    for (std::uint8_t b : lon) body.push_back(b);

    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::Advert, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    full.insert(full.end(), body.begin(), body.end());

    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full.data(), true);
    REQUIRE(d.ok);
    CHECK(d.hasLocation);
    CHECK_EQ(d.latitudeE6, 50000);
    CHECK_EQ(d.longitudeE6, -120000);
    CHECK_MSG(d.describe().find("loc=0.05000,-0.12000") != std::string::npos,
              "printed from the microdegree integers, not from a re-parse");
  }
  {
    // Flags promise a location the frame does not deliver. Reporting (0, 0) would
    // put null island on the operator's map.
    std::vector<std::uint8_t> body;
    for (int i = 0; i < 32; ++i) body.push_back(0);
    for (int i = 0; i < 4; ++i) body.push_back(0);
    for (int i = 0; i < 64; ++i) body.push_back(0);
    body.push_back(0x10);  // has location...
    body.push_back(0x01);  // ...and then two bytes instead of eight

    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::Advert, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    full.insert(full.end(), body.begin(), body.end());

    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full.data(), true);
    CHECK(!d.ok);
    CHECK_MSG(d.reason == Reason::Truncated, "a promised-but-absent location is truncation");
  }
  {
    // An advert with no appdata at all: legal, and it says only "a node".
    std::vector<std::uint8_t> body(100, 0);
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::Advert, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    full.insert(full.end(), body.begin(), body.end());
    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full.data(), true);
    CHECK(d.ok);
    CHECK(d.hasPublicKey);
    CHECK(!d.hasName);
  }
  {
    // Shorter than a public key.
    std::uint8_t full[] = {hdr(PayloadType::Advert, RouteType::Flood, PayloadVersion::V1), 0x00,
                           0x01, 0x02};
    const Packet pkt = parse(full, sizeof(full), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full, true);
    CHECK(!d.ok);
    CHECK(d.reason == Reason::Truncated);
  }

  // --- GRP_TXT: the readable message ---------------------------------------

  {
    std::uint8_t body[] = {0x00, 0x8F, 'h', 'e', 'l', 'l', 'o'};
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    for (std::uint8_t b : body) full.push_back(b);

    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full.data(), true);
    REQUIRE(d.ok);
    CHECK(d.decoder == DecoderId::MeshCoreGroupText);
    CHECK(d.hasChannelHash);
    CHECK_EQ(d.channelHash, 0x8F);
    CHECK(std::strcmp(d.text, "hello") == 0);
    CHECK(d.describe().find("chan=0x8F") != std::string::npos);
    CHECK(d.describe().find("text=\"hello\"") != std::string::npos);
  }
  {
    // Text suppression. The setting has to work on the same code path that would
    // otherwise emit the text, not on a separate one, or it is not a setting.
    std::uint8_t body[] = {0x00, 0x8F, 's', 'e', 'c', 'r', 'e', 't'};
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    for (std::uint8_t b : body) full.push_back(b);

    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    const Payload d = decodePayload(pkt, full.data(), false);
    REQUIRE(d.ok);
    CHECK_MSG(std::strcmp(d.text, "hello") != 0, "suppressed text must not appear");
    CHECK(std::strstr(d.text, "suppressed") != nullptr);
  }
  {
    // Terminal-hostile bytes must not reach the string.
    std::uint8_t body[] = {0x00, 0x8F, 'a', 0x00, 'b', 0x1B, 'c'};
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::GrpTxt, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    for (std::uint8_t b : body) full.push_back(b);
    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    const Payload d = decodePayload(pkt, full.data(), true);
    REQUIRE(d.ok);
    CHECK_MSG(std::strcmp(d.text, "a") == 0, "a NUL ends the name; an ESC must not be passed through");
  }

  // --- the encrypted payload classes --------------------------------------
  //
  // Structure is known, content is not. That is Partial, not unattributable, and
  // the difference is the whole triage taxonomy.

  {
    const PayloadType encrypted[] = {PayloadType::TxtMsg, PayloadType::Req, PayloadType::Response,
                                     PayloadType::Ack,     PayloadType::Path, PayloadType::AnonReq,
                                     PayloadType::Trace,   PayloadType::Multipart,
                                     PayloadType::GrpData,  PayloadType::RawCustom};
    for (PayloadType t : encrypted) {
      std::vector<std::uint8_t> full;
      full.push_back(hdr(t, RouteType::Flood, PayloadVersion::V1));
      full.push_back(0x00);
      for (int i = 0; i < 20; ++i) full.push_back(static_cast<std::uint8_t>(i));
      const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
      REQUIRE(pkt.wellFormed);
      const Payload d = decodePayload(pkt, full.data(), true);
      CHECK_MSG(d.decoder == DecoderId::MeshCoreV1, "the frame structure is still identified");
      CHECK_MSG(d.reason == Reason::MeshCoreEncrypted, "and the content declared unreadable");
      const Provenance prov = attribute(d.decoder, d.reason);
      CHECK_MSG(prov.attribution == Attribution::Partial,
                "a key-dependent payload is traceable to its protocol");
    }
  }

  // --- CONTROL: named, body not parsed -------------------------------------

  {
    std::vector<std::uint8_t> full;
    full.push_back(hdr(PayloadType::Control, RouteType::Flood, PayloadVersion::V1));
    full.push_back(0x00);
    full.push_back(0x02);
    full.push_back(0x2A);
    const Packet pkt = parse(full.data(), full.size(), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full.data(), true);
    CHECK(d.decoder == DecoderId::MeshCoreControl);
    CHECK(d.ok);
  }

  // --- reserved payload types ----------------------------------------------

  {
    std::uint8_t full[] = {hdr(PayloadType::Reserved0C, RouteType::Flood, PayloadVersion::V1), 0x00,
                           0x01, 0x02};
    const Packet pkt = parse(full, sizeof(full), kMeshCoreSync, true);
    REQUIRE(pkt.wellFormed);
    const Payload d = decodePayload(pkt, full, true);
    CHECK(!d.ok);
    CHECK_MSG(d.reason == Reason::ReservedValue, "naming a reserved type would invent meaning");
  }

  // --- refusal to decode off a malformed packet ----------------------------

  {
    // Handing decodePayload a packet the parser never produced must be refused,
    // not used as an excuse to read from an arbitrary offset.
    const Packet bad;
    const std::uint8_t data[] = {1, 2, 3, 4, 5, 6, 7, 8};
    const Payload d = decodePayload(bad, data, true);
    CHECK(!d.ok);
    const Payload e = decodePayload(bad, nullptr, true);
    CHECK(!e.ok);
  }
}
