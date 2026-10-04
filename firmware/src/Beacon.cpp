// SPDX-License-Identifier: MIT

#include "sniffer/Beacon.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include "sniffer/MeshtasticFrame.hpp"

namespace sniff {
namespace {

constexpr std::size_t kMaxFrameBytes = meshtastic::kHeaderBytes + 240;

std::string format(const char* fmt, ...) {
  char buf[192];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  const std::size_t len = static_cast<std::size_t>(n);
  return std::string(buf, len < sizeof(buf) ? len : sizeof(buf) - 1);
}

void putVarint(std::uint8_t* p, std::size_t* len, std::uint64_t v) {
  do {
    std::uint8_t b = static_cast<std::uint8_t>(v & 0x7Fu);
    v >>= 7;
    if (v != 0) b = static_cast<std::uint8_t>(b | 0x80u);
    p[*len] = b;
    ++(*len);
  } while (v != 0);
}

void putTag(std::uint8_t* p, std::size_t* len, std::uint32_t field, proto::WireType wire) {
  putVarint(p, len, (static_cast<std::uint64_t>(field) << 3) | static_cast<std::uint64_t>(wire));
}

void putFixed32(std::uint8_t* p, std::size_t* len, std::uint32_t field, std::uint32_t v) {
  putTag(p, len, field, proto::WireType::Fixed32);
  for (std::size_t i = 0; i < 4; ++i) {
    p[*len] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
    ++(*len);
  }
}

void putBytes(std::uint8_t* p, std::size_t* len, std::uint32_t field, const char* text,
              std::size_t textLen) {
  putTag(p, len, field, proto::WireType::LengthDelimited);
  putVarint(p, len, textLen);
  for (std::size_t i = 0; i < textLen; ++i) {
    p[*len] = static_cast<std::uint8_t>(text[i]);
    ++(*len);
  }
}

std::size_t textLength(const char* text, std::size_t cap) {
  if (text == nullptr) return 0;
  std::size_t n = 0;
  while (n < cap && text[n] != '\0') ++n;
  return n;
}

void label(BeaconFrame* f, const char* text) {
  std::size_t i = 0;
  for (; i + 1 < sizeof(f->label) && text[i] != '\0'; ++i) f->label[i] = text[i];
  f->label[i] = '\0';
}

}  // namespace

bool clampSchedule(BeaconSchedule* s) {
  if (s == nullptr) return false;

  // A count of zero is not a beacon. One is not either -- a single LoRa frame is
  // delivered roughly a third of the time, so a beacon sent once is a beacon that
  // usually does not arrive.
  if (s->count == 0) {
    s->count = 1;
  } else if (s->count > kMaxBeaconRepeats) {
    s->count = kMaxBeaconRepeats;
  }

  if (s->intervalMs < kMinBeaconIntervalMs) {
    s->intervalMs = kMinBeaconIntervalMs;
  }
  return true;
}

BeaconFrame meshCoreGroupText(std::uint8_t channelHash, const char* text) {
  BeaconFrame f;
  f.protocol = Protocol::MeshCore;

  const std::size_t n = textLength(text, kMaxBeaconText);

  // header 0x15 = v1, GRP_TXT, flood. path length 0x00 = no path, flooded.
  f.data[0] = static_cast<std::uint8_t>((0 << 6) |
                                        (static_cast<unsigned>(meshcore::PayloadType::GrpTxt) << 2) |
                                        static_cast<unsigned>(meshcore::RouteType::Flood));
  f.data[1] = 0x00;
  f.data[2] = 0x00;  // group flags
  f.data[3] = channelHash;

  std::size_t len = 4;
  for (std::size_t i = 0; i < n && len < kMaxFrameBytes; ++i) {
    f.data[len] = static_cast<std::uint8_t>(text[i]);
    ++len;
  }
  f.length = len;
  label(&f, format("meshcore grp_txt chan=0x%02X", static_cast<unsigned>(channelHash)).c_str());
  return f;
}

BeaconFrame meshtasticText(std::uint32_t fromNode, std::uint32_t toNode, const char* text) {
  BeaconFrame f;
  f.protocol = Protocol::Meshtastic;

  std::size_t len = 0;

  // The 16-byte header, plaintext, exactly as Meshtastic puts it on the air.
  f.data[len++] = meshtastic::kMagic0;
  f.data[len++] = meshtastic::kMagic1;
  f.data[len++] = meshtastic::kMagic2;
  f.data[len++] = static_cast<std::uint8_t>(toNode & 0xFFu);
  for (std::size_t i = 0; i < 4; ++i) {
    f.data[len++] = static_cast<std::uint8_t>((fromNode >> (8 * i)) & 0xFFu);
  }
  // Packet id. Zero is legal and is what an unidentified sender uses; the mesh
  // dedups on (from, id) so a beacon with a fixed zero is retried and recognised
  // as the same packet, which is the correct behaviour for a repeated beacon.
  for (std::size_t i = 0; i < 4; ++i) f.data[len++] = 0x00;
  f.data[len++] = 0x00;  // flags: hop limit 0, no ack
  f.data[len++] = meshtastic::kPrimaryChannelHash;
  f.data[len++] = 0x00;  // next hop
  f.data[len++] = 0x00;  // relay node

  // Data protobuf. The application payload is built first because its length has
  // to be known before the outer length prefix is written.
  const std::size_t n = textLength(text, kMaxBeaconText);
  std::uint8_t app[220];
  std::size_t appLen = 0;
  // The tag is part of the value. Writing a bare `1` put a field number 0 on the wire,
  // which is not a valid protobuf field at all: the frame decoded as "no portnum, no
  // text", and a real node would have shown the beacon as an unknown port rather than a
  // message.
  putTag(app, &appLen, 1, proto::WireType::Varint);
  putVarint(app, &appLen, 1);  // portnum = TEXT_MESSAGE_APP
  putBytes(app, &appLen, 1, text, n);  // field 1 of the app message: the text

  putFixed32(f.data, &len, 1, fromNode);
  putFixed32(f.data, &len, 2, toNode);
  // Channel 0 is the primary channel, whose body is plaintext, and is not written:
  // proto3 omits a scalar that holds its default, and the decoder applies the same
  // default. The previous version emitted a bare `0` here -- field number 0 again --
  // which is what stopped the whole Data message from parsing.
  putBytes(f.data, &len, 4, reinterpret_cast<const char*>(app), appLen);

  f.length = len;
  label(&f, format("meshtastic text from=!%08x", static_cast<unsigned>(fromNode)).c_str());
  return f;
}

BeaconPlan buildBeacon(const BeaconTarget* targets, std::size_t targetCount, const char* text,
                       const BeaconSchedule& scheduleIn, BeaconFrame* out, std::size_t outMax) {
  BeaconPlan plan;
  plan.reason[0] = '\0';

  if (targets == nullptr || out == nullptr || targetCount == 0) {
    std::snprintf(plan.reason, sizeof(plan.reason), "no targets: name a protocol to send on");
    return plan;
  }
  if (text == nullptr || text[0] == '\0') {
    std::snprintf(plan.reason, sizeof(plan.reason), "no text");
    return plan;
  }

  BeaconSchedule schedule = scheduleIn;
  if (!clampSchedule(&schedule)) {
    std::snprintf(plan.reason, sizeof(plan.reason), "schedule refused");
    return plan;
  }

  // Target-major ordering, so every network gets its first copy before any network
  // gets its second. A duty-cycle limit that stops the run halfway still covers
  // every network at least once.
  for (std::size_t rep = 0; rep < schedule.count; ++rep) {
    for (std::size_t t = 0; t < targetCount; ++t) {
      if (plan.built >= outMax) {
        plan.skipped = (schedule.count * targetCount) - plan.built;
        std::snprintf(plan.reason, sizeof(plan.reason),
                      "stopped after %u frames: the caller's buffer is full",
                      static_cast<unsigned>(plan.built));
        return plan;
      }

      const BeaconTarget& target = targets[t];
      BeaconFrame frame;
      switch (target.protocol) {
        case Protocol::MeshCore:
          frame = meshCoreGroupText(target.channelHash, text);
          break;
        case Protocol::Meshtastic:
          // Meshtastic's plaintext body only exists on the primary channel, so a
          // beacon aimed at any other channel hash is refused here rather than
          // producing a frame whose body is quietly wrong.
          if (target.channelHash != meshtastic::kPrimaryChannelHash) {
            ++plan.skipped;
            continue;
          }
          frame = meshtasticText(0x00000000u, 0xFFFFFFFFu, text);
          break;
        default:
          ++plan.skipped;
          continue;
      }
      out[plan.built] = frame;
      ++plan.built;
    }
  }
  return plan;
}

std::string describeBeacon(const BeaconFrame& f) {
  return std::string(protocolTag(f.protocol)) + " beacon " + f.label + " " +
         format("%uB", static_cast<unsigned>(f.length));
}

}  // namespace sniff
