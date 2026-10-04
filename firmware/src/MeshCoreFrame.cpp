// SPDX-License-Identifier: MIT

#include "sniffer/MeshCoreFrame.hpp"

#include <cstdarg>
#include <cstdio>
#include <string>

#include "sniffer/RfPlan.hpp"

namespace sniff {
namespace meshcore {
namespace {

std::string format(const char* fmt, ...) {
  char buf[160];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  const std::size_t len = static_cast<std::size_t>(n);
  return std::string(buf, len < sizeof(buf) ? len : sizeof(buf) - 1);
}

std::uint16_t readLe16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>(static_cast<std::uint16_t>(p[0]) |
                                    static_cast<std::uint16_t>(p[1] << 8));
}

}  // namespace

bool payloadTypeDefined(PayloadType t) {
  switch (t) {
    case PayloadType::Reserved0C:
    case PayloadType::Reserved0D:
    case PayloadType::Reserved0E:
      return false;
    default:
      return true;
  }
}

const char* payloadTypeName(PayloadType t) {
  switch (t) {
    case PayloadType::Req:
      return "req";
    case PayloadType::Response:
      return "response";
    case PayloadType::TxtMsg:
      return "txt_msg";
    case PayloadType::Ack:
      return "ack";
    case PayloadType::Advert:
      return "advert";
    case PayloadType::GrpTxt:
      return "grp_txt";
    case PayloadType::GrpData:
      return "grp_data";
    case PayloadType::AnonReq:
      return "anon_req";
    case PayloadType::Path:
      return "path";
    case PayloadType::Trace:
      return "trace";
    case PayloadType::Multipart:
      return "multipart";
    case PayloadType::Control:
      return "control";
    case PayloadType::Reserved0C:
      return "reserved_0c";
    case PayloadType::Reserved0D:
      return "reserved_0d";
    case PayloadType::Reserved0E:
      return "reserved_0e";
    case PayloadType::RawCustom:
      return "raw_custom";
    default:
      return "invalid";
  }
}

const char* routeTypeName(RouteType r) {
  switch (r) {
    case RouteType::TransportFlood:
      return "transport_flood";
    case RouteType::Flood:
      return "flood";
    case RouteType::Direct:
      return "direct";
    case RouteType::TransportDirect:
      return "transport_direct";
    default:
      return "invalid";
  }
}

const char* payloadVersionName(PayloadVersion v) {
  switch (v) {
    case PayloadVersion::V1:
      return "v1";
    case PayloadVersion::Reserved2:
      return "reserved_v2";
    case PayloadVersion::Reserved3:
      return "reserved_v3";
    case PayloadVersion::Reserved4:
      return "reserved_v4";
    default:
      return "invalid";
  }
}

bool readHeader(std::uint8_t header, RouteType* route, PayloadType* payload,
                PayloadVersion* version) {
  if (route == nullptr || payload == nullptr || version == nullptr) return false;
  *route = static_cast<RouteType>(header & 0x03);
  *payload = static_cast<PayloadType>((header >> 2) & 0x0F);
  *version = static_cast<PayloadVersion>((header >> 6) & 0x03);
  return true;
}

Packet parse(const std::uint8_t* data, std::size_t length, std::uint8_t syncWord,
             bool syncWordAvailable) {
  Packet p;

  if (data == nullptr || length < 1) {
    p.wellFormed = false;
    p.problem = Reason::NoiseOrTooShort;
    p.provenance = attribute(DecoderId::None, Reason::NoiseOrTooShort);
    return p;
  }

  p.header = data[0];
  (void)readHeader(p.header, &p.routeType, &p.payloadType, &p.payloadVersion);

  // A reserved payload version means a format this decoder was not written
  // against. Reading the rest of the frame would be inventing structure, so it
  // stops here and says so. That is a real result: it means somebody on this
  // band is running a newer MeshCore than this firmware knows about.
  if (p.payloadVersion != PayloadVersion::V1) {
    p.wellFormed = false;
    p.problem = Reason::ReservedValue;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::ReservedValue);
    return p;
  }

  std::size_t off = 1;

  // The two transport route types carry four extra bytes.
  if (p.routeType == RouteType::TransportFlood || p.routeType == RouteType::TransportDirect) {
    if (length < off + 4) {
      p.wellFormed = false;
      p.problem = Reason::Truncated;
      p.provenance = attribute(DecoderId::MeshCoreV1, Reason::Truncated);
      return p;
    }
    p.hasTransportCodes = true;
    p.transportCode1 = readLe16(data + off);
    p.transportCode2 = readLe16(data + off + 2);
    off += 4;
  }

  // The path-length byte. Not a byte count: hop count in bits 0-5, hash size
  // minus one in bits 6-7.
  if (length < off + 1) {
    p.wellFormed = false;
    p.problem = Reason::Truncated;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::Truncated);
    return p;
  }
  const std::uint8_t pathLenByte = data[off];
  ++off;

  p.hopCount = static_cast<std::uint8_t>(pathLenByte & 0x3F);
  const std::uint8_t hashSizeCode = static_cast<std::uint8_t>((pathLenByte >> 6) & 0x03);

  // 0b11 is reserved in the specification. It is not four-byte hashes, and
  // treating it as such would let a corrupt frame sail through with a plausible
  // path length.
  if (hashSizeCode == 0x03) {
    p.hashSizeReserved = true;
    p.wellFormed = false;
    p.problem = Reason::ReservedValue;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::ReservedValue);
    return p;
  }
  p.hashSize = static_cast<std::uint8_t>(hashSizeCode + 1);
  p.pathBytes = static_cast<std::size_t>(p.hopCount) * static_cast<std::size_t>(p.hashSize);

  if (p.pathBytes > kMaxPathBytes) {
    p.wellFormed = false;
    p.problem = Reason::ReservedValue;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::ReservedValue);
    return p;
  }

  if (length < off + p.pathBytes) {
    // The frame is shorter than its own path. Reported, not repaired.
    p.wellFormed = false;
    p.problem = Reason::Truncated;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::Truncated);
    return p;
  }
  off += p.pathBytes;

  p.payloadOffset = off;
  p.payloadLength = length - off;

  if (p.payloadLength > kMaxPayloadBytes) {
    p.wellFormed = false;
    p.problem = Reason::ReservedValue;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::ReservedValue);
    return p;
  }

  if (p.payloadLength == 0) {
    p.wellFormed = false;
    p.problem = Reason::Truncated;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::Truncated);
    return p;
  }

  // Structurally a MeshCore v1 frame. Whether its *content* is readable is the
  // payload decoder's business, not this one's.
  p.wellFormed = true;

  // Evidence note. The sync word is what tells us this is MeshCore at all; a
  // body that parses cleanly on MeshCore's geometry but arrived wearing somebody
  // else's sync byte is the interesting case the brief asks to surface, and it is
  // downgraded rather than discarded so the operator can see it.
  //
  // A wildcard is not "somebody else". Promiscuous capture reports 0x00 when no real
  // preamble byte was matched, and a byte that carries no information must not be
  // able to contradict anything -- so it is treated as absent here exactly as it is
  // in Classifier and PlanRegistry.
  const bool syncUsable = syncWordAvailable && !isWildcardSync(syncWord);
  const bool syncAgrees = syncUsable && syncWord == kMeshCoreSync;

  if (syncUsable && !syncAgrees && fromSyncWord(syncWord) != Protocol::MeshCore) {
    p.problem = Reason::KnownSyncUnknownBody;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::KnownSyncUnknownBody);
  } else {
    p.problem = Reason::FullyDecoded;
    p.provenance = attribute(DecoderId::MeshCoreV1, Reason::FullyDecoded);
  }
  return p;
}

std::string describe(const Packet& p) {
  std::string s = format("MC %s %s %s hops=%u hash=%uB payload=%uB",
                          payloadTypeName(p.payloadType), routeTypeName(p.routeType),
                          payloadVersionName(p.payloadVersion),
                          static_cast<unsigned>(p.hopCount),
                          static_cast<unsigned>(p.hashSize),
                          static_cast<unsigned>(p.payloadLength));
  if (!p.wellFormed) {
    s += format(" [%s]", reasonName(p.problem));
  }
  if (p.hasTransportCodes) {
    s += format(" tc=%04X/%04X", static_cast<unsigned>(p.transportCode1),
                static_cast<unsigned>(p.transportCode2));
  }
  return s;
}

}  // namespace meshcore
}  // namespace sniff
