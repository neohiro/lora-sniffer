// SPDX-License-Identifier: MIT
//
// MeshCorePayload -- reading what an unkeyed sniffer is allowed to read.
//
// MeshCore encrypts most of what it carries, and an honest sniffer says so
// rather than printing confident hex. Three payload classes, though, are
// documented as plaintext, and those are the ones that make the difference
// between a sniffer that is useful on a live mesh and one that is a spectrum
// analyser with extra steps:
//
//   ADVERT   a node announcing itself, with its role, location and name in the
//            clear. This is how a sniffer operator discovers *which nodes exist*
//            on a channel they hold no key for.
//   GRP_TXT  a group text message. Plaintext.
//   CONTROL  documented as unencrypted.
//
// A GRP_TXT is the frame this project exists to surface: on a MeshCore channel
// the sniffer holds no key for, group traffic is readable, and "what is being
// said on this frequency right now" becomes answerable by anyone standing in the
// same postcode. That is a genuinely useful capability and also a genuinely
// sensitive one, which is why the operator has to *ask* for it -- see
// docs/ATTRIBUTION.md on the plainText flag and why it defaults on only when the
// channel in use is one the operator configured.
//
// Everything here is decode-without-a-key. Nothing verifies a signature. A
// decoded ADVERT says what a sender *claimed*; whether the signature over that
// claim checks out is a question for the protocol stack holding the key, and
// pretending otherwise is how a sniffer becomes a forgery kit.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/MeshCoreFrame.hpp"

namespace sniff {
namespace meshcore {

// What a decoder managed to produce. Populated per payload type; unused fields
// stay at their defaults and `populated` says which of them mean anything.
struct Payload {
  DecoderId decoder = DecoderId::None;
  Reason reason = Reason::FullyDecoded;
  bool ok = false;

  // --- ADVERT -------------------------------------------------------------
  // Public key, timestamp and signature are read but never verified. They are
  // reported so an operator can correlate two adverts from the same node, which
  // is how a sniffer counts *nodes* rather than frames.
  std::uint8_t publicKey[32] = {};
  bool hasPublicKey = false;
  std::uint32_t advertTimestamp = 0;
  bool hasTimestamp = false;
  bool hasSignature = false;

  // Appdata flags. These are the reason an ADVERT is worth decoding.
  bool roleChat = false;
  bool roleRepeater = false;
  bool roleRoomServer = false;
  bool roleSensor = false;
  bool hasLocation = false;
  bool hasFeature1 = false;
  bool hasFeature2 = false;
  bool hasName = false;

  std::int32_t latitudeE6 = 0;
  std::int32_t longitudeE6 = 0;

  // Text, when the frame carries any: the node name, or the message itself.
  // Truncated to a fixed capacity so a hostile frame cannot exhaust the heap.
  static constexpr std::size_t kMaxTextBytes = 64;
  char text[kMaxTextBytes + 1] = {};
  std::size_t textLength = 0;
  bool textTruncated = false;

  // --- GRP_TXT ------------------------------------------------------------
  std::uint8_t channelHash = 0;
  bool hasChannelHash = false;
  std::uint8_t groupFlags = 0;

  // One-line description, safe for a terminal.
  std::string describe() const;
};

// Decode a payload given the already-parsed packet frame. The payload extent is read
// from p, so a caller cannot pair a correct Packet with a length that disagrees with
// it -- the one mistake that would otherwise turn into reading arbitrary offsets.
//
// plainText gates
// whether decoded text may be returned at all; when it is false the decoder
// still reports the structure and the identifiers but replaces the text with a
// redaction marker, so an operator who has turned text off cannot be handed it
// by a different code path.
Payload decodePayload(const Packet& p, const std::uint8_t* data, bool plainText);

// A node role as a short label, or "" when none is set.
const char* advertRoleName(const Payload& p);

}  // namespace meshcore
}  // namespace sniff
