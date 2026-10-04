// SPDX-License-Identifier: MIT

#include "sniffer/LoRaWanFrame.hpp"

#include <cstdarg>
#include <cstdio>

namespace sniff {
namespace lorawan {
namespace {

std::string format(const char* fmt, ...) {
  char buf[176];
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

std::uint32_t readLe32(const std::uint8_t* p) {
  return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
         (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

// A little-endian 64-bit integer in the *byte* order LoRaWAN uses for EUIs:
// transmitted least-significant byte first.
std::uint64_t readLsf64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
  }
  return v;
}

constexpr std::size_t kMicBytes = 4;

}  // namespace

const char* mTypeName(MType t) {
  switch (t) {
    case MType::JoinRequest:
      return "join-request";
    case MType::JoinAccept:
      return "join-accept";
    case MType::UnconfirmedDataUp:
      return "data-up-unconfirmed";
    case MType::UnconfirmedDataDown:
      return "data-down-unconfirmed";
    case MType::ConfirmedDataUp:
      return "data-up-confirmed";
    case MType::ConfirmedDataDown:
      return "data-down-confirmed";
    case MType::RejoinRequest:
      return "rejoin-request";
    case MType::Propagate:
      return "propagate";
    default:
      return "invalid";
  }
}

const char* className(Class c) {
  switch (c) {
    case Class::B:
      return "B";
    case Class::C:
      return "C";
    case Class::A:
    default:
      return "A";
  }
}

Frame parse(const std::uint8_t* data, std::size_t length) {
  Frame f;

  if (data == nullptr || length < 1) {
    f.wellFormed = false;
    f.problem = Reason::NoiseOrTooShort;
    f.provenance = attribute(DecoderId::None, Reason::NoiseOrTooShort);
    return f;
  }

  f.mType = static_cast<MType>((data[0] >> 5) & 0x07);
  f.major = static_cast<std::uint8_t>((data[0] >> 1) & 0x03);
  // Major 0 and 1 exist; anything above is a revision this decoder does not
  // know, and parsing its layout on a guess is exactly what this project exists
  // not to do.
  f.majorValid = (f.major == 0 || f.major == 1);

  // JoinRequest: MHDR then the join-request message, no frame header at all.
  if (f.mType == MType::JoinRequest) {
    // MHDR(1) + JoinEUI(8) + DevEUI(8) + DevNonce(2) + MIC(4) = 23 minimum.
    if (length < 23) {
      f.wellFormed = false;
      f.problem = Reason::Truncated;
      f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::Truncated);
      return f;
    }
    f.appEui = readLsf64(data + 1);
    f.devEui = readLsf64(data + 9);
    f.devNonce = readLe16(data + 17);
    f.micOffset = 19;
    f.micLength = length - 19;
    f.wellFormed = f.majorValid;
    if (!f.majorValid) {
      f.problem = Reason::ReservedValue;
      f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::ReservedValue);
      return f;
    }
    f.problem = Reason::FullyDecoded;
    f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::FullyDecoded);
    return f;
  }

  // Everything else is MACHeader + FHDR. 12 bytes minimum once the MIC is counted.
  if (length < 12) {
    f.wellFormed = false;
    f.problem = Reason::Truncated;
    f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::Truncated);
    return f;
  }

  f.minor = static_cast<std::uint8_t>(data[0] & 0x01);
  f.devAddr = readLe32(data + 1);
  f.fCtrl = data[5];
  f.adr = (f.fCtrl & 0x80) != 0;
  f.adrAckReq = (f.fCtrl & 0x40) != 0;
  f.ack = (f.fCtrl & 0x20) != 0;
  f.classB = (f.fCtrl & 0x10) != 0;
  f.downlinkClass = static_cast<Class>(f.fCtrl & 0x03);
  f.fCnt = readLe16(data + 6);

  const std::uint8_t fOptsLen = static_cast<std::uint8_t>(data[7] & 0x0F);
  const bool hasFPort = (data[7] & 0x80) == 0;

  f.payloadOffset = 8;
  f.fPort = hasFPort ? data[8] : 0;
  if (hasFPort) {
    f.payloadOffset = 9;
  }
  f.payloadOffset += fOptsLen;

  if (length <= f.payloadOffset) {
    // No room even for the MIC. Reported rather than clamped.
    f.wellFormed = false;
    f.problem = Reason::Truncated;
    f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::Truncated);
    return f;
  }

  f.micOffset = length - kMicBytes;
  if (f.micOffset < f.payloadOffset) {
    f.wellFormed = false;
    f.problem = Reason::Truncated;
    f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::Truncated);
    return f;
  }
  f.payloadLength = f.micOffset - f.payloadOffset;
  f.micLength = kMicBytes;

  if (!f.majorValid) {
    f.wellFormed = false;
    f.problem = Reason::ReservedValue;
    f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::ReservedValue);
    return f;
  }

  f.wellFormed = true;
  f.problem = Reason::FullyDecoded;
  f.provenance = attribute(DecoderId::LoRaWanPhy, Reason::FullyDecoded);
  return f;
}

std::string describe(const Frame& f) {
  if (f.mType == MType::JoinRequest) {
    if (!f.wellFormed) {
      return format("LW join-request [%s]", reasonName(f.problem));
    }
    // EUIs printed the way LoRaWAN tools print them: most significant byte first,
    // colon-separated. The bytes on air are the other way round.
    //
    // The trailing note is part of the summary rather than a comment, because a
    // LoRaWAN join request on a community frequency is the single most likely
    // thing for this tool to surface that is *not* a mesh node, and an operator
    // reading a capture at 2am needs to be told that in the line itself.
    return format(
        "LW join-request deveui=%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x appeui=%02x:%02x "
        "nonce=0x%04x -- LoRaWAN infrastructure, not a mesh node",
        static_cast<unsigned>((f.devEui >> 56) & 0xFF), static_cast<unsigned>((f.devEui >> 48) & 0xFF),
        static_cast<unsigned>((f.devEui >> 40) & 0xFF), static_cast<unsigned>((f.devEui >> 32) & 0xFF),
        static_cast<unsigned>((f.devEui >> 24) & 0xFF), static_cast<unsigned>((f.devEui >> 16) & 0xFF),
        static_cast<unsigned>((f.devEui >> 8) & 0xFF), static_cast<unsigned>(f.devEui & 0xFF),
        static_cast<unsigned>((f.appEui >> 56) & 0xFF), static_cast<unsigned>(f.appEui & 0xFF),
        static_cast<unsigned>(f.devNonce));
  }

  if (!f.wellFormed) {
    return format("LW %s [%s]", mTypeName(f.mType), reasonName(f.problem));
  }

  std::string s = format("LW %s devaddr=%08x fcnt=%u class=%c", mTypeName(f.mType),
                         static_cast<unsigned>(f.devAddr), static_cast<unsigned>(f.fCnt),
                         className(f.downlinkClass)[0]);
  if (f.adr) s += " adr";
  if (f.ack) s += " ack";
  s += format(" payload=%uB", static_cast<unsigned>(f.payloadLength));
  if (f.fPort != 0) {
    s += format(" fport=%u", static_cast<unsigned>(f.fPort));
  }
  return s;
}

}  // namespace lorawan
}  // namespace sniff
