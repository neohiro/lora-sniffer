// SPDX-License-Identifier: MIT
//
// Protocol -- the vocabulary every other module speaks.
//
// Kept deliberately small and deliberately identical to the enumeration the
// neohiro/meshcore-meshtastic-heltec-v4 bridge uses, so that a capture taken by
// one project and a capture taken by the other can be merged into one timeline
// without a translation table. Two projects that agree on six names are worth
// more than two projects that each invented their own.

#pragma once

#include <cstddef>
#include <cstdint>

namespace sniff {

// Protocol slots this firmware knows how to name. Slots are reserved, not
// implemented: Reticulum is here so the sync table has a stable shape and
// adding a framework is a table entry rather than a refactor.
enum class Protocol : std::uint8_t {
  Unknown = 0,
  MeshCore,
  Meshtastic,
  Reticulum,
  LoRaWan,
  Custom,
};

// Two-letter tag for an OLED column or a log line: "MC", "MT", "RT", "LW", "??".
const char* protocolTag(Protocol p);

const char* protocolName(Protocol p);

// Parse a tag or a full name back to a protocol. Case-insensitive on the name,
// exact on the tag. Returns false rather than guessing when the text is not a
// protocol, because a filter that silently accepts "meshcoree" would show an
// operator a confident empty result.
bool parseProtocol(const char* text, Protocol* out);

// ---------------------------------------------------------------------------
// The one byte
// ---------------------------------------------------------------------------

// Both protocols ride the same carrier, so the only thing separating a frame at
// the PHY layer is the LoRa sync word in the preamble. Reading it costs no
// decryption, no key lookup and no parsing, and it works on a frame too short to
// carry anything else.
//
// This table is the reason the whole idea works. It is also the reason a
// sniffer is honest about what it does not know: a radio in packet mode strips
// the byte and reports only match/no-match, so `syncWordAvailable` is false far
// more often than anyone would like, and every downstream module is required to
// cope rather than to assume.
constexpr std::uint8_t kMeshCoreSync = 0x12;
constexpr std::uint8_t kMeshtasticPublicSync = 0x2B;
constexpr std::uint8_t kReticulumSync = 0x42;
constexpr std::uint8_t kLoRaWanPublicSync = 0x34;

// Map one sync byte to a protocol. Unknown bytes map to Protocol::Unknown rather
// than defaulting to a mesh: on a shared band an unrecognised frame is far more
// likely to be somebody else's LoRa than ours, and guessing is how a sniffer
// starts filing a foreign network's traffic under our name.
Protocol fromSyncWord(std::uint8_t syncWord);

}  // namespace sniff
