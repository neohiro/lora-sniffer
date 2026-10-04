// SPDX-License-Identifier: MIT

#include "sniffer/Capture.hpp"

#include <cstdio>
#include <cstring>

#include "sniffer/DeviceTable.hpp"
#include "sniffer/LoRaWanFrame.hpp"
#include "sniffer/MeshtasticFrame.hpp"
#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/MeshCorePayload.hpp"
#include "sniffer/PlanRegistry.hpp"

namespace sniff {
namespace {

// Copy a bounded string into a fixed field, and say whether anything was copied.
bool takeName(char* dst, std::size_t cap, const char* src, std::size_t srcLen) {
  std::size_t n = 0;
  while (n < srcLen && n + 1 < cap) {
    dst[n] = src[n];
    ++n;
  }
  dst[n] = '\0';
  return n > 0;
}

std::uint32_t be32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}

void hexPrefix(const std::uint8_t* data, std::size_t length, std::size_t max, std::string* out) {
  const std::size_t n = (length < max) ? length : max;
  out->clear();
  out->reserve(n * 3 + 4);
  char buf[3];
  for (std::size_t i = 0; i < n; ++i) {
    const int w = std::snprintf(buf, sizeof(buf), "%02x", static_cast<unsigned>(data[i]));
    if (w <= 0) break;
    out->append(buf, 2);
    if (i + 1 < n) out->push_back(' ');
  }
  if (n < length) *out += " ...";
}

// ---------------------------------------------------------------------------
// MeshCore
// ---------------------------------------------------------------------------

void decodeMeshCore(Record* rec, const std::uint8_t* data, std::size_t length,
                    bool plainText) {
  namespace mc = meshcore;

  const mc::Packet p =
      mc::parse(data, length, rec->link.syncWord, rec->link.syncWordAvailable);
  if (!p.wellFormed) {
    rec->decoded.add("mc_status", reasonName(p.problem));
    rec->decoded.addHex("mc_hdr", p.header, 2);
    // A frame that claimed a structure it did not deliver is its own finding, and
    // folding it into "unknown" would hide it. The provenance keeps it.
    rec->provenance = p.provenance;
    return;
  }

  rec->decoded.add("mc_type", mc::payloadTypeName(p.payloadType));
  rec->decoded.add("mc_route", mc::routeTypeName(p.routeType));
  rec->decoded.add("hops", static_cast<unsigned long>(p.hopCount));
  rec->decoded.add("hash", static_cast<unsigned long>(p.hashSize));
  rec->decoded.add("plen", static_cast<unsigned long>(p.payloadLength));
  if (p.hasTransportCodes) {
    rec->decoded.addHex("tc1", p.transportCode1, 4);
    rec->decoded.addHex("tc2", p.transportCode2, 4);
  }

  const mc::Payload d = mc::decodePayload(p, data, plainText);

  // Start from the packet's own verdict, then let a deeper decoder replace it. Done
  // in one place rather than inside each case, which is what guarantees a GRP_TXT
  // reports `meshcore.grp_txt` rather than the generic `meshcore.v1`: the decoder's
  // name in the capture stream is what tells an operator which decoder to go and
  // improve.
  rec->provenance = p.provenance;
  if (d.decoder != DecoderId::None && d.decoder != DecoderId::MeshCoreV1) {
    rec->provenance = attribute(d.decoder, d.reason);
  }

  switch (d.decoder) {
    case DecoderId::MeshCoreAdvert:
      rec->decoded.add("mc_decoder", decoderIdName(DecoderId::MeshCoreAdvert));
      if (d.ok && d.hasPublicKey) {
        rec->decoded.addHex("key", be32(d.publicKey), 8);
        const char* role = mc::advertRoleName(d);
        if (role[0] != '\0') rec->decoded.add("role", role);
        if (d.hasLocation) {
          rec->decoded.addFloat("lat", static_cast<double>(d.latitudeE6) / 1e6, 5);
          rec->decoded.addFloat("lon", static_cast<double>(d.longitudeE6) / 1e6, 5);
        }
        if (d.textLength > 0) rec->decoded.add("name", d.text);

        // Identity: the node's public key prefix. MeshCore's own node hash is one
        // byte; four is what fits this table and what the firmware uses for
        // routing hashes, so it is also what a MeshCore client will recognise.
        rec->hasIdentity = true;
        rec->identityProtocol = Protocol::MeshCore;
        for (std::size_t i = 0; i < Record::kIdentityBytes; ++i) {
          rec->identity[i] = d.publicKey[i];
        }
        // A GRP_TXT has no path field at all, so hop count is genuinely unknown
        // rather than zero. Defaulting it to zero would put every MeshCore node at
        // the top of a shortest-path list, which is the sort of thing that looks
        // like a result.
        rec->hopsValid = false;

        if (role[0] != '\0') {
          if (std::strcmp(role, "repeater") == 0) rec->role = static_cast<std::uint8_t>(NodeRole::Repeater);
          else if (std::strcmp(role, "room_server") == 0) rec->role = static_cast<std::uint8_t>(NodeRole::RoomServer);
          else if (std::strcmp(role, "sensor") == 0) rec->role = static_cast<std::uint8_t>(NodeRole::Sensor);
          else rec->role = static_cast<std::uint8_t>(NodeRole::Chat);
        }
        if (d.textLength > 0) {
          rec->hasName = takeName(rec->name, sizeof(rec->name), d.text, d.textLength);
        }
      }
      break;

    case DecoderId::MeshCoreGroupText:
      rec->decoded.add("mc_decoder", decoderIdName(DecoderId::MeshCoreGroupText));
      if (d.ok) {
        rec->decoded.addHex("chan", d.channelHash, 2);
        rec->decoded.addHex("gflags", d.groupFlags, 2);
        if (d.textLength > 0) {
          rec->decoded.add("text", d.text);
          // A GRP_TXT names a channel, not a sender. The text is retained against
          // the entry for this channel so that "what has been said on this channel"
          // is answerable, but it is not attributed to a node, because nothing in
          // the frame says which node sent it.
          rec->hasText = takeName(rec->text, sizeof(rec->text), d.text, d.textLength);
        }
      }
      break;

    case DecoderId::MeshCoreControl:
      rec->decoded.add("mc_decoder", decoderIdName(DecoderId::MeshCoreControl));
      if (p.payloadLength >= 2) {
        rec->decoded.addHex("ctrl", (static_cast<std::uint32_t>(data[p.payloadOffset]) << 8) |
                                         static_cast<std::uint32_t>(data[p.payloadOffset + 1]),
                            4);
      }
      break;

    case DecoderId::None:
      break;

    case DecoderId::MeshCoreV1:
    default:
      // Reached for every payload type whose content is key-dependent. The
      // structure is named and the content is declared unreadable, which is the
      // Partial case rather than the unattributable one.
      rec->decoded.add("mc_decoder", decoderIdName(DecoderId::MeshCoreV1));
      rec->decoded.add("mc_body", reasonName(Reason::MeshCoreEncrypted));
      rec->provenance = attribute(DecoderId::MeshCoreV1, Reason::MeshCoreEncrypted);
      break;
  }
}

// ---------------------------------------------------------------------------
// Meshtastic
// ---------------------------------------------------------------------------

void decodeMeshtastic(Record* rec, const std::uint8_t* data, std::size_t length,
                      bool plainText) {
  namespace mt = meshtastic;

  const mt::Header h = mt::parse(data, length);
  if (!h.wellFormed) {
    rec->decoded.add("mt_status", reasonName(h.problem));
    rec->provenance = h.provenance;
    return;
  }

  rec->decoded.add("from", mt::nodeIdText(h.from).c_str());
  rec->decoded.addHex("mid", h.packetId, 8);
  rec->decoded.addHex("chan", h.channelHash, 2);
  rec->decoded.addHex("hops", (static_cast<std::uint32_t>(h.hopStart) << 8) | h.hopLimit, 3);
  if (h.wantAck) rec->decoded.add("wantack", "yes");
  if (h.viaMqtt) rec->decoded.add("via", "mqtt");
  rec->decoded.add("plen", static_cast<unsigned long>(h.payloadLength));

  // Identity and distance. Meshtastic's node number is exactly four bytes, and the
  // header carries the sender's original hop limit alongside the current one -- so
  // the number of hops this frame actually travelled is the difference between the
  // two. That is the shortest-path signal for this protocol, and it is free.
  rec->hasIdentity = true;
  rec->identityProtocol = Protocol::Meshtastic;
  rec->identity[0] = static_cast<std::uint8_t>(h.from & 0xFFu);
  rec->identity[1] = static_cast<std::uint8_t>((h.from >> 8) & 0xFFu);
  rec->identity[2] = static_cast<std::uint8_t>((h.from >> 16) & 0xFFu);
  rec->identity[3] = static_cast<std::uint8_t>((h.from >> 24) & 0xFFu);
  rec->hopsValid = true;
  rec->hops = static_cast<std::uint8_t>((h.hopStart - h.hopLimit) & 0x07);

  const std::uint8_t* body = data + h.payloadOffset;
  const mt::Data d = mt::parseData(body, h.payloadLength);
  mt::Decoded dec;

  if (!d.present) {
    // Either encrypted, or protobuf we could not walk. Both are honest answers
    // and the reason distinguishes them: "no key" is expected, "unwalkable" is a
    // finding.
    rec->provenance = attribute(DecoderId::MeshtasticHeader, d.problem);
    rec->decoded.add("mt_body", reasonName(d.problem));
    if (h.channelHash != mt::kPrimaryChannelHash) {
      rec->decoded.add("mt_note", "non-primary channel: payload is ciphertext by design");
    }
    return;
  }

  rec->provenance = attribute(DecoderId::MeshtasticData, Reason::FullyDecoded);
  if (d.to != 0) rec->decoded.add("to", mt::nodeIdText(d.to).c_str());
  if (d.channel != 0) {
    rec->decoded.add("mt_chan", static_cast<unsigned long>(d.channel));
  }

  dec = mt::decodePlaintext(d);
  if (!dec.ok) {
    rec->decoded.add("mt_body", "portnum not present in a plaintext payload");
    return;
  }

  rec->decoded.add("portnum", static_cast<unsigned long>(dec.portnum));
  if (dec.portNumLabel[0] != '\0') rec->decoded.add("port", dec.portNumLabel);

  // Only a text portnum carries text this decoder is willing to read out of
  // plaintext. Everything else is reported by number, which is honest and is
  // also enough for an operator to go and look at the schema.
  if (dec.portnum == 1 && dec.textLength > 0 && plainText) {
    rec->decoded.add("text", dec.text);
    rec->hasText = takeName(rec->text, sizeof(rec->text), dec.text, dec.textLength);
  }
}

// ---------------------------------------------------------------------------
// LoRaWAN
// ---------------------------------------------------------------------------

void decodeLoRaWan(Record* rec, const std::uint8_t* data, std::size_t length) {
  namespace lw = lorawan;

  const lw::Frame f = lw::parse(data, length);
  if (!f.wellFormed) {
    rec->decoded.add("lw_status", reasonName(f.problem));
    rec->provenance = f.provenance;
    return;
  }

  rec->decoded.add("mtype", lw::mTypeName(f.mType));
  rec->provenance = f.provenance;

  if (f.mType == lw::MType::JoinRequest) {
    // The one payload class in this whole repository that carries a device
    // identity in the clear, and the reason a survey of a frequency is possible
    // without a single key.
    rec->decoded.addHex("deveui", static_cast<std::uint32_t>(f.devEui >> 32), 8);
    rec->decoded.addHex("deveui_lo", static_cast<std::uint32_t>(f.devEui & 0xFFFFFFFFu), 8);
    rec->decoded.addHex("nonce", f.devNonce, 4);
    rec->decoded.add("lw_note", "LoRaWAN on a mesh frequency: infrastructure, not a mesh node");
    return;
  }

  rec->decoded.addHex("devaddr", f.devAddr, 8);
  rec->decoded.add("fcnt", static_cast<unsigned long>(f.fCnt));
  rec->decoded.add("class", lw::className(f.downlinkClass));
  rec->decoded.add("plen", static_cast<unsigned long>(f.payloadLength));
  if (f.adr) rec->decoded.add("adr", "yes");
  if (f.ack) rec->decoded.add("ack", "yes");
  if (f.fPort != 0) rec->decoded.add("fport", static_cast<unsigned long>(f.fPort));

  // Identity: the DevAddr, which is the closest thing LoRaWAN has to a node. A join
  // request has no DevAddr, so a device is not in the table until it has joined --
  // which is correct, and means the table shows deployed devices rather than
  // every radio that ever came up on the frequency.
  rec->hasIdentity = true;
  rec->identityProtocol = Protocol::LoRaWan;
  rec->identity[0] = static_cast<std::uint8_t>(f.devAddr & 0xFFu);
  rec->identity[1] = static_cast<std::uint8_t>((f.devAddr >> 8) & 0xFFu);
  rec->identity[2] = static_cast<std::uint8_t>((f.devAddr >> 16) & 0xFFu);
  rec->identity[3] = static_cast<std::uint8_t>((f.devAddr >> 24) & 0xFFu);
  // LoRaWAN is a star topology. A gateway hears its end devices directly, always,
  // so the distance is one hop and saying anything else would be inventing a mesh
  // that does not exist.
  rec->hopsValid = true;
  rec->hops = 1;
}

// ---------------------------------------------------------------------------
// Nothing recognised it
// ---------------------------------------------------------------------------

void decodeUnattributed(Record* rec, const std::uint8_t* data, std::size_t length,
                        std::uint8_t maxBytes) {
  // This is the frame the brief is about, so it gets the most detail: the reason
  // in full, the fingerprint to group by, and every byte the radio gave us.
  rec->decoded.add("reason", reasonName(rec->provenance.reason));
  rec->decoded.add("why", reasonDetail(rec->provenance.reason));

  std::string hex;
  if (data != nullptr) hexPrefix(data, length, maxBytes, &hex);
  rec->decoded.add("hex", hex.c_str());
  if (length < 8) {
    rec->decoded.add("note", "shorter than any structure this firmware decodes");
  }
}

}  // namespace

bool CaptureEngine::setFilter(const char* spec) {
  FilterSpec parsed;
  char error[96];
  if (!parseFilter(spec, &parsed, error, sizeof(error))) return false;
  filter_ = parsed;
  return true;
}

void CaptureEngine::reset() {
  counters_.reset();
  repeats_.clear();
  seq_ = 0;
  resetRecord(&record_);
}

const Record& CaptureEngine::capture(const std::uint8_t* data, std::size_t length,
                                     const LinkEvidence& link, const RfParams& listenPlan,
                                     std::uint32_t timestampMs) {
  resetRecord(&record_);
  Record& rec = record_;

  ++seq_;
  rec.seq = seq_;
  rec.timestampMs = timestampMs;
  rec.link = link;
  rec.listenPlan = listenPlan;

  // --- 1. corrupt and noise, before anything is parsed ----------------------
  rec.corrupt = (link.crcCheck == Check::Failed);
  rec.noise = likelyNoise(link);

  // --- 2. classification ---------------------------------------------------
  Input in;
  in.data = data;
  in.length = (data == nullptr) ? 0 : length;
  in.link = link;
  in.listenPlan = listenPlan;
  const Verdict v = classify(in);
  rec.protocol = v.protocol;
  rec.provenance = v.provenance;

  // --- 3. decode, only for a protocol that survived step 1 -----------------
  //
  // The `!rec.noise` guard is the important one: nothing below this line should
  // ever run on bytes the radio refused at the preamble.
  if (!rec.noise && data != nullptr && length > 0) {
    switch (v.protocol) {
      case Protocol::MeshCore:
        decodeMeshCore(&rec, data, length, options_.plainText);
        break;
      case Protocol::Meshtastic:
        decodeMeshtastic(&rec, data, length, options_.plainText);
        break;
      case Protocol::LoRaWan:
        decodeLoRaWan(&rec, data, length);
        break;
      case Protocol::Reticulum:
      case Protocol::Custom:
      case Protocol::Unknown:
      default:
        break;
    }
  }

  if (rec.decoded.count == 0) {
    decodeUnattributed(&rec, data == nullptr ? rec.data : data, length, options_.maxBytes);
  }

  // --- the network verdict, now that the body has had its say --------------
  const bool bodyMatched = (rec.provenance.decoder != DecoderId::None) &&
                           rec.provenance.attribution != Attribution::Unattributed;
  rec.verdict = judge(listenPlan, link, rec.protocol, bodyMatched);

  // --- 4. fingerprint, over raw bytes and the sync word ---------------------
  rec.fingerprint =
      fingerprintFrame(data == nullptr ? rec.data : data, length, link.syncWord,
                       link.syncWordAvailable);
  rec.repeatCount = repeats_.observe(rec.fingerprint);

  // --- carry the bytes, bounded --------------------------------------------
  const std::size_t maxBytes = options_.maxBytes;
  const std::size_t keep = (length < maxBytes) ? length : maxBytes;
  if (options_.includeBytes && data != nullptr && keep > 0 && keep <= sizeof(rec.data)) {
    std::memcpy(rec.data, data, keep);
  }
  rec.length = static_cast<std::uint8_t>(keep);

  // --- the filter, then the counters ---------------------------------------
  rec.filtered = !filterMatches(filter_, rec);
  counters_.observe(rec);
  counters_.rollWindow(timestampMs);

  return rec;
}

}  // namespace sniff
