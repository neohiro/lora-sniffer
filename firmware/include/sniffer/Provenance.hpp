// SPDX-License-Identifier: MIT
//
// Provenance -- naming the library that can read a frame, and saying so plainly
// when none of them can.
//
// The brief behind this repository asks for a sniffer that transmits *all*
// received data back to the operator, with proper identifiers for what each
// message could mean, and easy to find the messages that cannot be traced back
// to the protocol stack inside the LoRa device. That last clause is the one
// that decides the design, because "untraceable" is only useful if it is
// *classified*.
//
// A sniffer that simply prints hex has failed the brief in the most likely
// real-world case. On a shared band the majority of what arrives is frequently
// not the network you care about, and the interesting question is never "what
// were these bytes" but "why could nothing here read them, and is it the same
// nothing every time".
//
// So every frame carries a provenance record: which decoder claimed it, whether
// that decoder fully understood it, and if not, exactly which of a small fixed
// set of reasons applied. The reasons are enumerated rather than free text
// because a fixed set can be counted, filtered, alerted on and tested -- and
// because "unknown" as a single bucket hides the two cases that matter most:
//
//   - *We recognised the protocol but hold no key.* Not a bug. Not a mystery.
//     The operator already knows why.
//   - *Nothing recognised it.* This is the real finding. It is either a foreign
//     network, a protocol nobody has written a decoder for, or a corrupt
//     capture. Those three want completely different responses from the
//     operator, so they get three different reasons.
//
// On "the minilib inside the device". The brief is read here as the protocol
// stack the node itself runs -- in the neohiro stack that is MeshCore's own
// crypto/packet implementation (the `minilib` tree it vendors) behind the v1
// packet format, and Meshtastic's AES-CCM behind the MeshHeader. What this
// module makes precise is the *registry of decoders*: a frame is traceable when
// one of the registered decoders can parse it, and the decoder's id is recorded
// so an operator can say "the meshcore decoder read it", not merely "we think it
// was MeshCore". Where that reading of the brief is wrong, the registry is one
// table in Provenance.cpp and nothing else moves.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Protocol.hpp"

namespace sniff {

// ---------------------------------------------------------------------------
// The decoder registry
// ---------------------------------------------------------------------------

// Every decoder this firmware ships, named. Adding one is a row here plus a
// parse function plus a registry entry in Provenance.cpp -- which is the point:
// a decoder with no name could not be reported, and an unnamed decoder is
// indistinguishable from no decoder at all.
//
// The string values are part of the on-the-wire contract with tools/sniffctl.py
// and must not be changed casually. They appear verbatim in the JSONL capture
// stream and in the operator's saved reports.
enum class DecoderId : std::uint8_t {
  None = 0,
  MeshCoreV1,        // the MeshCore v1 packet format: header, path, payload
  MeshCoreAdvert,    // MeshCore ADVERT appdata, which is plaintext
  MeshCoreGroupText, // MeshCore GRP_TXT, which is plaintext
  MeshCoreControl,   // MeshCore CONTROL, documented as unencrypted
  MeshtasticHeader,  // the plaintext MeshHeader that wraps every Meshtastic frame
  MeshtasticData,    // the `Data` protobuf, readable only when unencrypted
  LoRaWanPhy,        // the LoRaWAN PHY header, always plaintext
  ReticulumRNode,    // placeholder: sync word known, header spec not vendored
};

// Registry id, e.g. "meshcore.v1". Stable, lowercase, dotted.
const char* decoderIdName(DecoderId id);

// The decoder that owns a protocol, for reporting. Protocol::MeshCore is owned
// by MeshCoreV1 even when a deeper decoder did the reading.
DecoderId owningDecoder(Protocol protocol);

// ---------------------------------------------------------------------------
// Attribution
// ---------------------------------------------------------------------------

// How far a decoder got. Three states, because "understood it" and "claimed it
// and then hit a wall" are different facts and an operator debugging a foreign
// network needs to tell them apart.
enum class Attribution : std::uint8_t {
  // A decoder parsed the frame and produced named fields from it.
  Attributed = 0,
  // A decoder recognised the frame as its own but could not read past a point
  // -- no key, a reserved subtype, a truncated buffer. The protocol is known;
  // the content is not.
  Partial = 1,
  // No decoder claimed the frame. This is the bucket the brief asks to be easy
  // to find.
  Unattributed = 2,
};

const char* attributionName(Attribution a);

// Why a frame ended up where it did. Enumerated so it can be counted.
enum class Reason : std::uint8_t {
  // The happy path, and the only reason that means "we understood this".
  FullyDecoded = 0,

  // --- Protocol known, content withheld. Not a finding; the operator already
  // --- knows these exist. They exist because the sender chose to encrypt.

  // Meshtastic payload on a channel whose key this sniffer does not hold, or
  // any encrypted payload: the MeshHeader is plaintext and the body is not.
  EncryptedNoKey,
  // MeshCore payload the decoder cannot read without the channel's key.
  MeshCoreEncrypted,

  // --- Protocol known, frame malformed. A real finding about the air. ---

  // A frame was shorter than the structure it claims to be.
  Truncated,
  // The structure parsed but a field held a value the specification reserves.
  ReservedValue,
  // The radio reported a CRC failure, so the bytes are not trustworthy.
  CorruptOnAir,

  // --- Nothing recognised it. The bucket that matters most. ---

  // A recognised-looking sync word, but no decoder recognised the bytes. Either
  // a protocol on a known sync word that this firmware does not decode, or a
  // frame from a channel that has diverged from the public format.
  KnownSyncUnknownBody,
  // A sync word nobody in the registry has a row for. On a shared band this is
  // the single most likely outcome and is usually simply another community.
  ForeignSyncWord,
  // No sync byte was available (packet mode strips it) and nothing in the bytes
  // was conclusive. This is the honest answer, and it is why promiscuous
  // capture is not optional for this firmware.
  NoEvidenceAtAll,
  // Bytes arrived, no sync byte, no magic, but the body is structured enough
  // that it is almost certainly a protocol rather than noise. Worth surfacing.
  AnonymousButStructured,
  // Too short or too weak to say anything.
  NoiseOrTooShort,
};

const char* reasonName(Reason r);

// One-line explanation for the operator, sized for an OLED and a terminal.
const char* reasonDetail(Reason r);

// True for the reasons that mean "nobody at all could read this". This is the
// filter the brief asks for and the one tools/sniffctl.py exposes as
// --only-unknown.
bool isUntraceable(Reason r);

// True for the reasons that indicate something worth investigating on the air,
// as opposed to a frame that was correctly and deliberately unreadable.
bool isAnomaly(Reason r);

// The number of Reason enumerators, exactly. The static assertion is the point:
// adding a reason to the enum without growing this is a compile error, not a
// silent out-of-bounds write in the counters three files away.
constexpr std::size_t kReasonCount = 11;
static_assert(static_cast<std::size_t>(Reason::NoiseOrTooShort) + 1 == kReasonCount,
              "kReasonCount is stale: a Reason was added or removed above");

// The complete record attached to every capture.
struct Provenance {
  DecoderId decoder = DecoderId::None;
  Attribution attribution = Attribution::Unattributed;
  Reason reason = Reason::NoEvidenceAtAll;

  // How many decoders claimed the frame. More than one means two formats
  // overlap, which is worth reporting because it means one of them is about to
  // be wrong on some other frame.
  std::uint8_t claimants = 0;
};

// Compose a provenance record from a decoder's own claim.
Provenance attribute(DecoderId decoder, Reason reason);

}  // namespace sniff
