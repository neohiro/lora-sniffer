// SPDX-License-Identifier: MIT

#include "sniffer/MeshtasticFrame.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace sniff {
namespace meshtastic {
namespace {

std::string format(const char* fmt, ...) {
  char buf[200];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  const std::size_t len = static_cast<std::size_t>(n);
  return std::string(buf, len < sizeof(buf) ? len : sizeof(buf) - 1);
}

// Meshtastic's TEXT_MESSAGE_APP, the one portnum whose body a sniffer can read
// without a schema.
constexpr std::uint32_t kPortTextMessage = 1;

// `Data` field numbers, from the published schema.
constexpr std::uint32_t kFieldFrom = 1;
constexpr std::uint32_t kFieldTo = 2;
constexpr std::uint32_t kFieldChannel = 3;
constexpr std::uint32_t kFieldPayload = 4;

// Meshtastic's encrypted-payload marker: the first byte of a ciphertext body is
// 0x01 (packet type "encrypted"). Observing it is a strong hint, not proof, so
// it is reported as a hint rather than asserted.
constexpr std::uint8_t kEncryptedMarker = 0x01;

void takeText(Decoded* out, const std::uint8_t* src, std::size_t avail) {
  std::size_t n = 0;
  while (n < avail && n < 64) {
    const std::uint8_t c = src[n];
    if (c == 0x00 || c < 0x09 || (c > 0x0D && c < 0x20) || c == 0x7F) break;
    out->text[n] = static_cast<char>(c);
    ++n;
  }
  out->text[n] = '\0';
  out->textLength = n;
  out->textTruncated = (n == 64) && (n < avail);
}

}  // namespace

bool hasMagic(const std::uint8_t* data, std::size_t length) {
  if (data == nullptr || length < 3) return false;
  return data[0] == kMagic0 && data[1] == kMagic1 && data[2] == kMagic2;
}

std::uint8_t hopLimit(const Header& h) { return static_cast<std::uint8_t>(h.flags & 0x07); }
bool wantAck(const Header& h) { return (h.flags & 0x08) != 0; }
bool viaMqtt(const Header& h) { return (h.flags & 0x10) != 0; }
std::uint8_t hopStart(const Header& h) { return static_cast<std::uint8_t>((h.flags >> 5) & 0x07); }

Header parse(const std::uint8_t* data, std::size_t length) {
  Header h;

  if (!hasMagic(data, length)) {
    h.wellFormed = false;
    h.problem = Reason::NoEvidenceAtAll;
    h.provenance = attribute(DecoderId::None, Reason::NoEvidenceAtAll);
    return h;
  }

  if (length < kHeaderBytes) {
    h.wellFormed = false;
    h.problem = Reason::Truncated;
    h.provenance = attribute(DecoderId::MeshtasticHeader, Reason::Truncated);
    return h;
  }

  h.toLowByte = data[3];
  h.from = static_cast<std::uint32_t>(data[4]) | (static_cast<std::uint32_t>(data[5]) << 8) |
           (static_cast<std::uint32_t>(data[6]) << 16) |
           (static_cast<std::uint32_t>(data[7]) << 24);
  h.packetId = static_cast<std::uint32_t>(data[8]) | (static_cast<std::uint32_t>(data[9]) << 8) |
               (static_cast<std::uint32_t>(data[10]) << 16) |
               (static_cast<std::uint32_t>(data[11]) << 24);
  h.flags = data[12];
  h.channelHash = data[13];
  h.nextHop = data[14];
  h.relayNode = data[15];

  h.hopLimit = hopLimit(h);
  h.wantAck = wantAck(h);
  h.viaMqtt = viaMqtt(h);
  h.hopStart = hopStart(h);

  h.payloadOffset = kHeaderBytes;
  h.payloadLength = length - kHeaderBytes;
  h.wellFormed = true;

  // A frame with no body at all is not a message; it is a header with nothing
  // behind it. Reported as truncated rather than as a successful parse, because
  // counting it as a decoded Meshtastic frame would overstate what was learned.
  if (h.payloadLength == 0) {
    h.wellFormed = false;
    h.problem = Reason::Truncated;
    h.provenance = attribute(DecoderId::MeshtasticHeader, Reason::Truncated);
    return h;
  }

  // The header was readable either way. Whether the body is readable is a
  // separate, second question, answered by parseData().
  h.problem = Reason::FullyDecoded;
  h.provenance = attribute(DecoderId::MeshtasticHeader, Reason::FullyDecoded);
  return h;
}

Data parseData(const std::uint8_t* data, std::size_t length) {
  Data d;
  if (data == nullptr || length == 0) {
    d.problem = Reason::Truncated;
    return d;
  }

  // The encrypted marker. Nothing here can read a ciphertext, so say that
  // instead of walking it as protobuf and producing fields out of noise.
  if (data[0] == kEncryptedMarker) {
    d.problem = Reason::EncryptedNoKey;
    return d;
  }

  proto::Reader r(data, length);
  bool sawKnownField = false;

  while (!r.done()) {
    proto::Tag tag;
    if (!r.next(&tag)) {
      d.problem = Reason::Truncated;
      d.present = sawKnownField;
      return d;
    }

    switch (tag.field) {
      case kFieldFrom:
        if (tag.wire != proto::WireType::Fixed32 || !r.fixed32(&d.from)) {
          d.problem = Reason::Truncated;
          d.present = sawKnownField;
          return d;
        }
        sawKnownField = true;
        break;

      case kFieldTo:
        if (tag.wire != proto::WireType::Fixed32 || !r.fixed32(&d.to)) {
          d.problem = Reason::Truncated;
          d.present = sawKnownField;
          return d;
        }
        sawKnownField = true;
        break;

      case kFieldChannel: {
        std::uint64_t v = 0;
        if (tag.wire != proto::WireType::Varint || !r.varint(&v)) {
          d.problem = Reason::Truncated;
          d.present = sawKnownField;
          return d;
        }
        d.channel = static_cast<std::uint32_t>(v);
        sawKnownField = true;
        break;
      }

      case kFieldPayload:
        if (tag.wire != proto::WireType::LengthDelimited ||
            !r.bytes(&d.payload, &d.payloadLength)) {
          d.problem = Reason::Truncated;
          d.present = sawKnownField;
          return d;
        }
        d.havePayload = true;
        sawKnownField = true;
        break;

      default:
        // Unknown or uninteresting. Skipped, not guessed at -- and a skip that
        // runs off the end is a truncation, not a shrug.
        if (!r.skip(tag.wire)) {
          d.problem = Reason::Truncated;
          d.present = sawKnownField;
          return d;
        }
        break;
    }
  }

  d.present = sawKnownField;
  if (!sawKnownField) d.problem = Reason::AnonymousButStructured;
  return d;
}

const char* portNumName(std::uint32_t portnum) {
  // Only the handful an operator can act on are named. The full enumeration is a
  // couple of hundred entries owned by the Meshtastic project; duplicating a
  // stale copy of it in this repository would be a liability, and reporting the
  // number is not a loss -- the number *is* the identifier.
  switch (portnum) {
    case 1:
      return "TEXT_MESSAGE_APP";
    case 2:
      return "REMOTE_HARDWARE_APP";
    case 3:
      return "POSITION_APP";
    case 4:
      return "NODEINFO_APP";
    case 5:
      return "ROUTING_APP";
    case 6:
      return "ADMIN_APP";
    case 7:
      return "TEXT_MESSAGE_COMPRESSED_APP";
    case 8:
      return "WAYPOINT_APP";
    case 67:
      return "TRACEROUTE_APP";
    case 70:
      return "NEIGHBORINFO_APP";
    case 71:
      return "ATAK_PLUGIN";
    case 73:
      return "MAP_REPORT_APP";
    case 74:
      return "POWERSTRESS_APP";
    case 75:
      return "RETICULUM_TUNNEL_APP";
    case 76:
      return "CAYENNE_APP";
    case 109:
      return "PRIVATE_APP";
    case 256:
      return "ATAK_FORWARDER";
    case 257:
      return "MAX";
    default:
      return "";
  }
}

Decoded decodePlaintext(const Data& d) {
  Decoded out;
  if (!d.present || !d.havePayload || d.payload == nullptr || d.payloadLength == 0) {
    return out;
  }

  // The application payload is a message whose field 1 is the portnum, followed by
  // the portnum-specific body. Only one portnum's body is read -- TEXT_MESSAGE_APP,
  // whose body is itself a message whose field 1 is the text -- because that is the
  // only one whose schema is worth carrying a decoder for on a device with this much
  // flash. Everything else is reported by its number, which is the honest answer and
  // is enough to go and look the schema up.
  proto::Reader app(d.payload, d.payloadLength);
  bool sawPortnum = false;
  const std::uint8_t* textPtr = nullptr;
  std::size_t textLen = 0;

  while (!app.done()) {
    proto::Tag tag;
    if (!app.next(&tag)) return out;
    if (tag.field == 1 && tag.wire == proto::WireType::Varint) {
      std::uint64_t v = 0;
      if (!app.varint(&v)) return out;
      out.portnum = static_cast<std::uint32_t>(v);
      out.portNumLabel = portNumName(out.portnum);
      sawPortnum = true;
      continue;
    }

    if (sawPortnum && out.portnum == kPortTextMessage && tag.wire == proto::WireType::LengthDelimited) {
      // A second length-delimited field after the portnum is the text body. Held as
      // a pointer into the caller's buffer rather than copied, so nothing is
      // allocated and nothing can overflow.
      if (!app.bytes(&textPtr, &textLen)) return out;
      continue;
    }

    if (!app.skip(tag.wire)) return out;
  }

  if (!sawPortnum) return out;
  out.ok = true;

  if (textPtr != nullptr && textLen > 0) takeText(&out, textPtr, textLen);
  return out;
}

std::string nodeIdText(std::uint32_t id) {
  return format("!%08x", static_cast<unsigned>(id));
}

std::string describe(const Header& h, const Decoded& d) {
  std::string s = format("MT from=%s id=0x%08x chan=0x%02x hops=%u/%u", nodeIdText(h.from).c_str(),
                          static_cast<unsigned>(h.packetId), static_cast<unsigned>(h.channelHash),
                          static_cast<unsigned>(h.hopStart), static_cast<unsigned>(h.hopLimit));
  if (h.wantAck) s += " wantack";
  if (h.viaMqtt) s += " mqtt";

  if (d.ok && d.textLength > 0) {
    s += format(" text=\"%s\"", d.text);
  } else if (h.wellFormed) {
    s += format(" payload=%uB", static_cast<unsigned>(h.payloadLength));
  }
  if (!h.wellFormed) {
    s += format(" [%s]", reasonName(h.problem));
  }
  return s;
}

}  // namespace meshtastic
}  // namespace sniff
