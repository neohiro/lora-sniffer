// SPDX-License-Identifier: MIT
//
// Classifier -- which mesh does this frame belong to, and how sure are we?
//
// This is the routing decision in front of every decoder, and it is the same
// decision the neohiro bridge makes on one radio serving two meshes, extended
// for the case where the answer may be "neither" and where the sniffer needs to
// be able to say *why*.
//
// Four independent signals, consulted in a deliberate order:
//
//   1. **Sync word.** Cheapest, works on a frame too short to carry anything
//      else, and requires no key. Where the radio gives it up this is the
//      primary signal.
//   2. **MeshHeader magic.** The plaintext 0x95 0x33 0x16 that opens every
//      Meshtastic frame. Read in-band from the same buffer as the payload, so it
//      is a stronger witness than a preamble byte and it is what rescues
//      Meshtastic *private* channels -- those derive their sync word from the
//      channel hash, so they arrive wearing a byte no table here has ever seen.
//   3. **Structure.** A header byte that parses as MeshCore v1, or an MHDR whose
//      major version is valid. Weakest of the three, because a short random
//      frame has a non-trivial chance of satisfying a loose structural test.
//      Used only when nothing better is available, and always reported as
//      structure rather than as an identification.
//   4. **Carrier.** The modulation matched a known network. Not a protocol
//      claim at all -- on EU_868 both MeshCore and Meshtastic use it.
//
// Two rules the bridge established, kept here for the same reasons:
//
//   * **A contradiction resolves in favour of the in-band magic.** If the sync
//     byte says one mesh and the MeshHeader says another, the capture is
//     corrupt, and the bytes in the buffer are better evidence than the
//     preamble that preceded them.
//   * **Unknown means unknown.** A frame nothing recognises stays Unknown. On a
//     shared band somebody else's LoRa is far more likely to be arriving than
//     ours, and a classifier that defaults to a mesh is how a sniffer starts
//     filing a foreign community's traffic under our names. The cost of that
//     mistake -- an operator chasing a network that does not exist -- is far
//     higher than the cost of admitting ignorance on a frame.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"
#include "sniffer/RfPlan.hpp"

namespace sniff {

enum class EvidenceKind : std::uint8_t {
  None = 0,
  SyncWord,
  MeshHeaderMagic,
  MeshCoreHeader,
  LoRaWanPhy,
  CarrierOnly,
};

const char* evidenceKindName(EvidenceKind k);

struct Evidence {
  EvidenceKind kind = EvidenceKind::None;

  // Short, human, and safe to print on an OLED: "sync 0x12", "magic 95:33:16",
  // "structure hdr=0x2C", "carrier 869.525/250/SF11".
  char detail[40] = {};
};

// Bounded because the number of distinct signals is fixed and small. A sniffer
// that could emit unbounded reasoning about a frame is a sniffer that can be
// made to allocate by a frame.
constexpr std::size_t kMaxEvidence = 4;

// How the verdict was reached. Reported, never inferred by the caller: "it said
// MeshCore" and "it said MeshCore because of a preamble byte" are different
// statements and an operator chasing a phantom mesh needs the second one.
enum class Basis : std::uint8_t {
  Nothing = 0,
  SyncOnly,
  MagicOnly,
  StructureOnly,
  CarrierOnly,
  SyncAndMagic,
  MagicOverrodeSync,
};

const char* basisName(Basis b);

struct Verdict {
  Protocol protocol = Protocol::Unknown;
  Basis basis = Basis::Nothing;

  std::uint8_t evidenceCount = 0;
  Evidence evidence[kMaxEvidence];

  // True when two independent signals named the same protocol. Single-signal
  // verdicts are allowed -- the sync word is enough on its own -- but the
  // operator is entitled to know that it was only ever one signal.
  bool corroborated = false;

  // True when the sync byte was a wildcard, or the radio stripped it. These
  // verdicts rest on something weaker and the capture stream says so.
  bool syncUnavailable = false;

  Reason reason = Reason::NoEvidenceAtAll;
  Provenance provenance;

  // One-line justification, e.g. "MeshCore on sync word 0x12, body unclaimed".
  //
  // 128 bytes rather than "just enough for the screen": the longest sentence this
  // module produces is the magic-over-sync override, and truncating it to fit a 96
  // byte buffer cut off the words "corrupt capture" -- which are the entire point
  // of that sentence. A truncated explanation is worse than a shorter complete one.
  char because[128] = {};
};

struct Input {
  const std::uint8_t* data = nullptr;
  std::size_t length = 0;
  LinkEvidence link;
  RfParams listenPlan;
};

// Classify. Pure: no I/O, no globals, no allocation. The decoders are consulted
// only for structure, and only when the cheap signals have not already decided.
Verdict classify(const Input& in);

}  // namespace sniff
