// SPDX-License-Identifier: MIT

#include "sniffer/MeshCorePayload.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace sniff {
namespace meshcore {
namespace {

constexpr const char* kRedacted = "[text suppressed by filter]";

std::string format(const char* fmt, ...) {
  char buf[224];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  const std::size_t len = static_cast<std::size_t>(n);
  return std::string(buf, len < sizeof(buf) ? len : sizeof(buf) - 1);
}

std::uint32_t readLe32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// Copy printable UTF-8-ish bytes out of a frame, bounded by both the caller's
// capacity and the frame. Two reasons for the bounds rather than a trust: an
// arbitrary byte in the middle of a name would otherwise run off the end of the
// buffer into whatever followed it, and a name field with no length prefix has
// to be treated as hostile until proven otherwise.
void takeText(Payload* out, const std::uint8_t* src, std::size_t avail) {
  std::size_t n = 0;
  while (n < avail && n < Payload::kMaxTextBytes) {
    const std::uint8_t c = src[n];
    // Stop at anything that would corrupt a terminal or a UTF-8 stream.
    if (c == 0x00 || c < 0x09 || (c > 0x0D && c < 0x20) || c == 0x7F) break;
    out->text[n] = static_cast<char>(c);
    ++n;
  }
  out->text[n] = '\0';
  out->textLength = n;
  out->textTruncated = (n < avail) && (n == Payload::kMaxTextBytes);
}

// ---------------------------------------------------------------------------
// ADVERT
// ---------------------------------------------------------------------------

// Layout: public key (32) | timestamp (4) | signature (64) | appdata
// Appdata: flags (1) [latitude (4) longitude (4)] [feature1 (2)] [feature2 (2)]
//         [name ...]
Payload decodeAdvert(const std::uint8_t* d, std::size_t len) {
  Payload p;
  p.decoder = DecoderId::MeshCoreAdvert;

  if (len < 32 + 4) {
    p.reason = Reason::Truncated;
    return p;
  }

  std::memcpy(p.publicKey, d, 32);
  p.hasPublicKey = true;
  p.advertTimestamp = readLe32(d + 32);
  p.hasTimestamp = true;

  std::size_t off = 36;
  p.hasSignature = (len - off) >= 64;
  if (p.hasSignature) off += 64;

  if (off >= len) {
    // A 100-byte advert with no appdata is legal -- it is a node announcing
    // itself and nothing more -- but it is not a frame this decoder can say
    // anything more about than "a node".
    p.reason = Reason::FullyDecoded;
    p.ok = true;
    return p;
  }

  const std::uint8_t flags = d[off];
  ++off;
  p.roleChat = (flags & 0x01) != 0;
  p.roleRepeater = (flags & 0x02) != 0;
  p.roleRoomServer = (flags & 0x03) == 0x03;
  p.roleSensor = (flags & 0x04) != 0;
  p.hasLocation = (flags & 0x10) != 0;
  p.hasFeature1 = (flags & 0x20) != 0;
  p.hasFeature2 = (flags & 0x40) != 0;
  p.hasName = (flags & 0x80) != 0;

  // Flags say a field is present; the buffer says whether it actually is. A
  // frame that promises a location and then stops is truncated, and reporting it
  // as a node at (0, 0) would put a null island on the operator's map.
  if (p.hasLocation) {
    if (len < off + 8) {
      p.reason = Reason::Truncated;
      return p;
    }
    p.latitudeE6 = static_cast<std::int32_t>(readLe32(d + off));
    p.longitudeE6 = static_cast<std::int32_t>(readLe32(d + off + 4));
    off += 8;
  }
  if (p.hasFeature1) {
    if (len < off + 2) {
      p.reason = Reason::Truncated;
      return p;
    }
    off += 2;
  }
  if (p.hasFeature2) {
    if (len < off + 2) {
      p.reason = Reason::Truncated;
      return p;
    }
    off += 2;
  }
  if (p.hasName) {
    takeText(&p, d + off, len - off);
  }

  p.reason = Reason::FullyDecoded;
  p.ok = true;
  return p;
}

// ---------------------------------------------------------------------------
// GRP_TXT
// ---------------------------------------------------------------------------

// Layout: flags (1) | channel hash (1) | text
// The flags byte carries a signature-present bit; the signature, when present,
// follows the text and is not parsed.
Payload decodeGrpTxt(const std::uint8_t* d, std::size_t len) {
  Payload p;
  p.decoder = DecoderId::MeshCoreGroupText;

  if (len < 2) {
    p.reason = Reason::Truncated;
    return p;
  }
  p.groupFlags = d[0];
  p.channelHash = d[1];
  p.hasChannelHash = true;
  takeText(&p, d + 2, len - 2);

  p.reason = Reason::FullyDecoded;
  p.ok = true;
  return p;
}

}  // namespace

const char* advertRoleName(const Payload& p) {
  // The flags are a small set rather than a bitmask for the role nibble, so a
  // node with two roles set is reported as the higher one and the summary line
  // says nothing false about it.
  if (p.roleRoomServer) return "room_server";
  if (p.roleSensor) return "sensor";
  if (p.roleRepeater) return "repeater";
  if (p.roleChat) return "chat";
  return "";
}

std::string Payload::describe() const {
  const Payload& p = *this;
  switch (p.decoder) {
    case DecoderId::MeshCoreAdvert: {
      if (!p.ok) {
        return format("advert [%s]", reasonName(p.reason));
      }
      std::string s = format("advert key=%02X%02X%02X%02X", p.publicKey[0], p.publicKey[1],
                             p.publicKey[2], p.publicKey[3]);
      const char* role = advertRoleName(p);
      if (role[0] != '\0') {
        s += format(" role=%s", role);
      }
      if (p.hasLocation) {
        // Printed with three decimals of a degree from the integer microdegrees,
        // which is the resolution the field actually carries.
        s += format(" loc=%.5f,%.5f", static_cast<double>(p.latitudeE6) / 1e6,
                    static_cast<double>(p.longitudeE6) / 1e6);
      }
      if (p.hasName && p.textLength > 0) {
        s += format(" name=%s", p.text);
      } else if (!p.hasName) {
        s += " name=(none)";
      }
      return s;
    }

    case DecoderId::MeshCoreGroupText: {
      if (!p.ok) {
        return format("grp_txt [%s]", reasonName(p.reason));
      }
      return format("grp_txt chan=0x%02X flags=0x%02X text=\"%s\"",
                    static_cast<unsigned>(p.channelHash), static_cast<unsigned>(p.groupFlags),
                    p.textLength > 0 ? p.text : "");
    }

    case DecoderId::MeshCoreControl:
      return format("control [%s]", p.ok ? "read" : reasonName(p.reason));

    default:
      return format("payload [%s]", reasonName(p.reason));
  }
}

Payload decodePayload(const Packet& pkt, const std::uint8_t* data, bool plainText) {
  // Trust the packet's own offsets rather than recomputing them. A caller that
  // hands over a packet it did not get from parse() gets a refusal, not a read
  // from an arbitrary offset.
  if (!pkt.wellFormed || data == nullptr) {
    Payload p;
    p.reason = Reason::Truncated;
    return p;
  }
  // The payload extent comes from the packet the parser produced, not from a length
  // passed alongside it. Passing both invites a caller to hand over a length that
  // disagrees with the offsets the parser derived, and the only defence is to
  // refuse the second source.
  const std::uint8_t* d = data + pkt.payloadOffset;
  const std::size_t len = pkt.payloadLength;

  if (!payloadTypeDefined(pkt.payloadType)) {
    Payload p;
    p.reason = Reason::ReservedValue;
    return p;
  }

  Payload p;
  switch (pkt.payloadType) {
    case PayloadType::Advert:
      p = decodeAdvert(d, len);
      break;
    case PayloadType::GrpTxt:
      p = decodeGrpTxt(d, len);
      break;
    case PayloadType::Control:
      // Documented as unencrypted, but the sub-format is chosen by a type byte
      // this decoder does not enumerate. Naming the frame as CONTROL and saying
      // the body is not parsed is honest; guessing at the sub-format is not.
      p.decoder = DecoderId::MeshCoreControl;
      p.ok = true;
      break;

    case PayloadType::TxtMsg:
    case PayloadType::Req:
    case PayloadType::Response:
    case PayloadType::Ack:
    case PayloadType::Path:
    case PayloadType::AnonReq:
    case PayloadType::Trace:
    case PayloadType::Multipart:
    case PayloadType::GrpData:
    case PayloadType::RawCustom:
    default:
      // These carry encrypted or key-dependent content. The structure is known
      // and the content is not, which is exactly the Partial case.
      p.decoder = DecoderId::MeshCoreV1;
      p.reason = Reason::MeshCoreEncrypted;
      p.ok = false;
      return p;
  }

  if (p.ok && !plainText && p.textLength > 0) {
    // Redact rather than omit, so a suppressed frame is visibly suppressed
    // instead of looking like a frame that happened to carry nothing.
    std::strncpy(p.text, kRedacted, sizeof(p.text));
    p.textLength = std::strlen(kRedacted);
    p.textTruncated = false;
  }
  return p;
}

}  // namespace meshcore
}  // namespace sniff
