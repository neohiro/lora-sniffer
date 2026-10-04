// SPDX-License-Identifier: MIT
//
// MeshtasticFrame -- the Meshtastic LoRa header, which is the reason an unkeyed
// sniffer can say anything at all about a Meshtastic network.
//
// Meshtastic encrypts its payload but sends a 16-byte header in the clear,
// immediately after the three magic bytes. That header names the sender, the
// packet id, the hop limit and -- critically -- the one-byte channel hash that
// selects the key. So a sniffer with no keys at all can still answer the
// questions an operator actually asks on a shared band:
//
//   * who is talking          -> `from`, per node
//   * how much of it there is -> packet counts per sender
//   * which channel           -> the hash byte, and therefore whether the
//                                payload is one this build could ever read
//   * how far it got          -> hop limit and hop start
//
// The layout, per the Meshtastic project's own protocol documentation:
//
//   0x00  3 B  magic 0x95 0x33 0x16, sent in the clear
//   0x03  1 B  destination node id, low byte only; the full `to` is in the body
//   0x04  4 B  from        (uint32, little-endian)
//   0x08  4 B  packet id   (uint32, little-endian; also the AES-CTR nonce seed)
//   0x0C  1 B  flags
//   0x0D  1 B  channel hash
//   0x0E  1 B  next hop    (routing hint)
//   0x0F  1 B  relay node  (previous hop)
//   0x10  ..   encrypted payload, or a plaintext `Data` when channel is 0
//
// Flag bits: 0-2 hop limit, 3 want-ack, 4 via-MQTT, 5-7 hop start.
//
// The one thing this decoder will not do is decrypt. When the channel hash is
// non-zero the body is AES-CCM ciphertext and the honest report is
// `encrypted-no-key`, carrying every header field that *is* readable. That
// distinction -- 16 bytes of named fields plus an unreadable body, versus no
// information at all -- is the whole reason this file exists.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Proto.hpp"
#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"

namespace sniff {
namespace meshtastic {

inline constexpr std::uint8_t kMagic0 = 0x95;
inline constexpr std::uint8_t kMagic1 = 0x33;
inline constexpr std::uint8_t kMagic2 = 0x16;

// Magic + the rest of the fixed header.
constexpr std::size_t kHeaderBytes = 16;

// The channel hash that means "the well-known public channel", whose payload is
// sent in the clear. Every other value selects a PSK this sniffer does not hold.
constexpr std::uint8_t kPrimaryChannelHash = 0x00;

// Read the plaintext magic. Three unambiguous bytes, readable even when the
// radio handed over no sync byte at all -- which is what rescues Meshtastic
// private channels, whose sync word is derived from the channel hash and is
// therefore a byte this firmware has never seen.
bool hasMagic(const std::uint8_t* data, std::size_t length);

struct Header {
  std::uint8_t toLowByte = 0;
  std::uint32_t from = 0;
  std::uint32_t packetId = 0;
  std::uint8_t flags = 0;
  std::uint8_t channelHash = 0;
  std::uint8_t nextHop = 0;
  std::uint8_t relayNode = 0;

  // Decoded flag fields.
  std::uint8_t hopLimit = 0;
  bool wantAck = false;
  bool viaMqtt = false;
  std::uint8_t hopStart = 0;

  std::size_t payloadOffset = kHeaderBytes;
  std::size_t payloadLength = 0;

  bool wellFormed = false;
  Reason problem = Reason::FullyDecoded;
  Provenance provenance;
};

std::uint8_t hopLimit(const Header& h);
bool wantAck(const Header& h);
bool viaMqtt(const Header& h);
std::uint8_t hopStart(const Header& h);

Header parse(const std::uint8_t* data, std::size_t length);

// The `Data` protobuf, readable only when the payload was not encrypted.
struct Data {
  bool present = false;
  std::uint32_t from = 0;
  std::uint32_t to = 0;
  std::uint32_t channel = 0;
  bool havePayload = false;
  const std::uint8_t* payload = nullptr;
  std::size_t payloadLength = 0;
  Reason problem = Reason::FullyDecoded;
};

// Parse the plaintext `Data` body. Field numbers are the published ones:
// from=1, to=2, channel=3, payload=4, want_ack=9, hop_limit=11.
Data parseData(const std::uint8_t* data, std::size_t length);

// A port number this decoder names. Everything else is reported by number, which
// is the honest thing to do for an enumeration with two hundred entries.
const char* portNumName(std::uint32_t portnum);

// What a portnum-carrying plaintext payload says, when it is a text message.
// `text` is bounded and NUL-terminated; `ok` says whether there was one.
struct Decoded {
  bool ok = false;
  std::uint32_t portnum = 0;
  const char* portNumLabel = "";
  std::size_t textLength = 0;
  char text[65] = {};
  bool textTruncated = false;
};

// Read the `portnum`-tagged application payload: field 1 is the portnum, and for
// TEXT_MESSAGE_APP the rest is the `Data` app message whose field 1 is the text.
Decoded decodePlaintext(const Data& d);

// One-line summary, e.g.
//   "MT from=!1a2b3c4 id=0x0000beef chan=0x8f hops=3/7 wantack payload=23B encrypted"
std::string describe(const Header& h, const Decoded& d);

// The `!deadbeef` form Meshtastic clients use for node ids.
std::string nodeIdText(std::uint32_t id);

}  // namespace meshtastic
}  // namespace sniff
