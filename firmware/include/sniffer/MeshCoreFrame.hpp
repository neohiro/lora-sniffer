// SPDX-License-Identifier: MIT
//
// MeshCoreFrame -- the MeshCore v1 packet format, parsed without a key.
//
// Source of truth: the MeshCore project's own docs/packet_format.md, which
// describes v1 as used by firmware v1.12.0 and later. The layout is
//
//     [header][transport_codes?][path_length][path][payload]
//
// where the single header byte packs a payload version, a payload type and a
// route type. That packing is the whole reason this decoder is worth writing:
// one byte of a 20-byte frame tells you the protocol, the message class, the
// routing mode and the hash geometry, all before any cryptography runs.
//
// What this decoder deliberately does *not* do is verify a MAC, decrypt
// anything, or claim that a frame is authentic. It reads structure. Structure is
// all an unkeyed sniffer has, and reporting "this claims to be a GRP_TXT with a
// 3-hop 2-byte-hash path" is a real, useful, honest observation -- whereas
// "this is a MeshCore group text from node 1a2b3c" would be four separate
// unverified claims stacked on top of each other.
//
// The path-length byte is the field most likely to be got wrong by anyone
// implementing this from memory, so it is worth spelling out: it is *not* a byte
// count. Bits 0-5 are the hop count and bits 6-7 are the hash size minus one,
// so 0x45 is five hops of two-byte hashes and consumes ten bytes. Treating it
// as a length is the classic way to end up parsing somebody's payload as a path.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"

namespace sniff {
namespace meshcore {

// The route type, from the low two bits of the header.
enum class RouteType : std::uint8_t {
  TransportFlood = 0,
  Flood = 1,
  Direct = 2,
  TransportDirect = 3,
};

// The payload type, from bits 2-5 of the header.
enum class PayloadType : std::uint8_t {
  Req = 0x0,
  Response = 0x1,
  TxtMsg = 0x2,
  Ack = 0x3,
  Advert = 0x4,
  GrpTxt = 0x5,
  GrpData = 0x6,
  AnonReq = 0x7,
  Path = 0x8,
  Trace = 0x9,
  Multipart = 0xA,
  Control = 0xB,
  Reserved0C = 0xC,
  Reserved0D = 0xD,
  Reserved0E = 0xE,
  RawCustom = 0xF,
};

// Payload version, from the high two bits of the header. Only v1 exists; the
// rest are reserved and a frame claiming one is reported as reserved rather than
// parsed on a guess.
enum class PayloadVersion : std::uint8_t {
  V1 = 0,
  Reserved2 = 1,
  Reserved3 = 2,
  Reserved4 = 3,
};

// Documented ceilings. A frame exceeding these is not a MeshCore v1 frame.
constexpr std::size_t kMaxPathBytes = 64;
constexpr std::size_t kMaxPayloadBytes = 184;

// True when a payload type has a defined meaning in the specification. The
// three reserved values do not, and saying so is the whole point -- a sniffer
// that names a reserved type invents meaning.
bool payloadTypeDefined(PayloadType t);

const char* payloadTypeName(PayloadType t);
const char* routeTypeName(RouteType t);
const char* payloadVersionName(PayloadVersion v);

struct Packet {
  // Raw header byte, reported verbatim so the operator can check the parse.
  std::uint8_t header = 0;

  RouteType routeType = RouteType::Flood;
  PayloadType payloadType = PayloadType::Req;
  PayloadVersion payloadVersion = PayloadVersion::V1;

  // Present only for the two transport route types.
  bool hasTransportCodes = false;
  std::uint16_t transportCode1 = 0;
  std::uint16_t transportCode2 = 0;

  // Path geometry, decoded from the packed path_length byte.
  std::uint8_t hopCount = 0;
  std::uint8_t hashSize = 1;
  bool hashSizeReserved = false;  // bits 6-7 were 0b11, which is reserved
  std::size_t pathBytes = 0;

  // Offset of the payload within the frame the caller handed us, so the caller
  // can decode in place without a copy.
  std::size_t payloadOffset = 0;
  std::size_t payloadLength = 0;

  // True when every length in the frame added up and the declared structures fit
  // inside the buffer. False frames are still reported -- with `problem` set --
  // because "this frame is 6 bytes long and claims a 10-byte path" is exactly
  // the sort of thing an operator hunting an unknown frame needs to see.
  bool wellFormed = false;
  Reason problem = Reason::FullyDecoded;

  Provenance provenance;
};

// Parse a MeshCore v1 frame.
//
// `syncWordAvailable` and `syncWord` come from the radio. A MeshCore frame
// without a 0x12 sync byte is still parsed, because a private channel may derive
// a different sync word -- but the result is marked downgraded, and the caller is
// expected to notice that the evidence was weaker.
Packet parse(const std::uint8_t* data, std::size_t length, std::uint8_t syncWord,
             bool syncWordAvailable);

// Just the header byte. Cheap enough to call on every frame before deciding
// whether the full parse is worth doing, which is what the classifier does.
bool readHeader(std::uint8_t header, RouteType* route, PayloadType* payload,
                PayloadVersion* version);

// One-line summary for a log line, e.g.
//   "MC grp_txt flood v1 hops=3 hash=2B payload=12B"
std::string describe(const Packet& p);

}  // namespace meshcore
}  // namespace sniff
