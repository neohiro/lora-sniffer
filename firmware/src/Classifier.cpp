// SPDX-License-Identifier: MIT

#include "sniffer/Classifier.hpp"

#include <cstdio>
#include <cstring>

#include "sniffer/LoRaWanFrame.hpp"
#include "sniffer/MeshtasticFrame.hpp"
#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/PlanRegistry.hpp"

namespace sniff {
namespace {

void setBecause(char* dst, std::size_t cap, const char* text) {
  std::size_t i = 0;
  for (; i + 1 < cap && text[i] != '\0'; ++i) dst[i] = text[i];
  dst[i] = '\0';
}

// Adds an evidence entry whose detail is a single formatted hex byte. Every
// structural signal in this file is "some byte parsed as something", so one
// helper covers all of them and there is no path that can add evidence with an
// empty detail.
void addEvidenceHex(Verdict* v, EvidenceKind kind, const char* label, std::uint8_t value) {
  if (v->evidenceCount >= kMaxEvidence) return;
  Evidence& e = v->evidence[v->evidenceCount];
  e.kind = kind;
  const int n = std::snprintf(e.detail, sizeof(e.detail), "%s 0x%02X", label,
                              static_cast<unsigned>(value));
  if (n < 0) e.detail[0] = '\0';
  ++v->evidenceCount;
}

void addEvidenceText(Verdict* v, EvidenceKind kind, const char* detail) {
  if (v->evidenceCount >= kMaxEvidence) return;
  Evidence& e = v->evidence[v->evidenceCount];
  e.kind = kind;
  std::size_t i = 0;
  for (; i + 1 < sizeof(e.detail) && detail[i] != '\0'; ++i) e.detail[i] = detail[i];
  e.detail[i] = '\0';
  ++v->evidenceCount;
}

}  // namespace

const char* evidenceKindName(EvidenceKind k) {
  switch (k) {
    case EvidenceKind::SyncWord:
      return "sync";
    case EvidenceKind::MeshHeaderMagic:
      return "magic";
    case EvidenceKind::MeshCoreHeader:
      return "structure";
    case EvidenceKind::LoRaWanPhy:
      return "structure";
    case EvidenceKind::CarrierOnly:
      return "carrier";
    case EvidenceKind::None:
    default:
      return "none";
  }
}

const char* basisName(Basis b) {
  switch (b) {
    case Basis::SyncAndMagic:
      return "sync+magic";
    case Basis::MagicOverrodeSync:
      return "magic-over-sync";
    case Basis::MagicOnly:
      return "magic";
    case Basis::SyncOnly:
      return "sync";
    case Basis::StructureOnly:
      return "structure";
    case Basis::CarrierOnly:
      return "carrier";
    case Basis::Nothing:
    default:
      return "nothing";
  }
}

Verdict classify(const Input& in) {
  Verdict v;

  const bool haveSync = in.link.syncWordAvailable && !isWildcardSync(in.link.syncWord);
  v.syncUnavailable = !haveSync;

  if (in.link.syncWordAvailable && isWildcardSync(in.link.syncWord)) {
    // A wildcard is recorded and then barred from voting, exactly as the bridge
    // does. A byte that carries no information must never decide anything.
    addEvidenceText(&v, EvidenceKind::None, "wildcard sync");
  }

  const bool magic = meshtastic::hasMagic(in.data, in.length);
  const Protocol fromSync = haveSync ? fromSyncWord(in.link.syncWord) : Protocol::Unknown;

  // --- Signal 1+2: sync word and MeshHeader magic ----------------------------

  if (magic) {
    addEvidenceText(&v, EvidenceKind::MeshHeaderMagic, "magic 95:33:16");
  }
  if (haveSync && fromSync != Protocol::Unknown) {
    addEvidenceHex(&v, EvidenceKind::SyncWord, "sync", in.link.syncWord);
  }

  if (magic && fromSync != Protocol::Unknown) {
    v.protocol = Protocol::Meshtastic;
    if (fromSync == Protocol::Meshtastic) {
      v.basis = Basis::SyncAndMagic;
      v.corroborated = true;
      setBecause(v.because, sizeof(v.because),
                 "sync word and MeshHeader magic agree on Meshtastic");
    } else {
      // The bridge's rule, kept: a disagreement means a corrupted preamble, and
      // the bytes read in-band from the same buffer are the better witness.
      v.basis = Basis::MagicOverrodeSync;
      setBecause(v.because, sizeof(v.because),
                 "MeshHeader magic overrides a sync word that named another protocol; "
                 "treating this as a corrupt capture");
    }
    v.reason = Reason::FullyDecoded;
    v.provenance = attribute(DecoderId::MeshtasticHeader, Reason::FullyDecoded);
    return v;
  }

  if (magic) {
    // The path that keeps private channels working: no usable sync byte, but three
    // unambiguous plaintext bytes at the front of the buffer.
    v.protocol = Protocol::Meshtastic;
    v.basis = Basis::MagicOnly;
    setBecause(v.because, sizeof(v.because),
               "MeshHeader magic only; a private channel derives its own sync word");
    v.reason = Reason::FullyDecoded;
    v.provenance = attribute(DecoderId::MeshtasticHeader, Reason::FullyDecoded);
    return v;
  }

  if (fromSync != Protocol::Unknown) {
    v.protocol = fromSync;
    v.basis = Basis::SyncOnly;
    setBecause(v.because, sizeof(v.because), "LoRa sync word alone");
    v.reason = Reason::FullyDecoded;

    if (fromSync == Protocol::Reticulum) {
      // Honest rather than aspirational. The sync word is known; the frame header
      // is not vendored here, so this sniffer cannot read Reticulum bodies and
      // says so instead of implying it can.
      v.reason = Reason::KnownSyncUnknownBody;
      v.provenance = attribute(DecoderId::None, Reason::KnownSyncUnknownBody);
      setBecause(v.because, sizeof(v.because),
                 "Reticulum sync word, but no RNode header decoder is vendored here");
      return v;
    }

    v.provenance = attribute(owningDecoder(fromSync), Reason::FullyDecoded);
    return v;
  }

  // --- Signal 3: structure --------------------------------------------------
  //
  // Only reached when neither the sync word nor the magic decided anything, which
  // in practice means the radio stripped the preamble byte. A structural read is a
  // guess with good odds, and it is labelled as one.

  if (in.data != nullptr && in.length >= 2) {
    // Both probes run, and the results are compared, because they genuinely
    // overlap. A byte of 0x40 decomposes as a valid MeshCore v1 header (version 1,
    // REQ, transport-flood) *and* as a valid LoRaWAN MHDR (unconfirmed data up,
    // major 0). Neither test is strong alone: a MeshCore header byte satisfies
    // "decomposes into some payload type" for all 256 values, and an MHDR has only
    // two valid major versions, so a random byte satisfies it half the time.
    //
    // When both fit, this module does not pick one. It reports Unknown and says a
    // sync byte would settle it, which is the truth: without the preamble byte
    // there is no evidence separating the two, and a classifier that picks the
    // likelier one is confidently wrong about every frame that falls the other way.
    const meshcore::Packet mc = meshcore::parse(in.data, in.length, in.link.syncWord,
                                                in.link.syncWordAvailable);
    const lorawan::Frame lw = lorawan::parse(in.data, in.length);

    const bool mcFits = mc.wellFormed;
    const bool lwFits = lw.wellFormed && lw.majorValid;

    if (mcFits && lwFits) {
      v.protocol = Protocol::Unknown;
      v.basis = Basis::StructureOnly;
      addEvidenceText(&v, EvidenceKind::None, "structure fits two protocols");
      setBecause(v.because, sizeof(v.because),
                 "this first byte fits both a MeshCore v1 header and a LoRaWAN MHDR, and "
                 "there is no sync byte to say which. Reported as unknown rather than guessed");
      v.reason = Reason::KnownSyncUnknownBody;
      v.provenance = attribute(DecoderId::None, Reason::KnownSyncUnknownBody);
      return v;
    }

    if (mcFits) {
      v.protocol = Protocol::MeshCore;
      v.basis = Basis::StructureOnly;
      addEvidenceHex(&v, EvidenceKind::MeshCoreHeader, "structure hdr", in.data[0]);
      setBecause(v.because, sizeof(v.because),
                 "MeshCore v1 header parsed with no sync byte available; structure, not "
                 "identification");
      v.reason = Reason::FullyDecoded;
      v.provenance = attribute(DecoderId::MeshCoreV1, Reason::FullyDecoded);
      return v;
    }

    if (lwFits) {
      v.protocol = Protocol::LoRaWan;
      v.basis = Basis::StructureOnly;
      addEvidenceHex(&v, EvidenceKind::LoRaWanPhy, "structure mhdr", in.data[0]);
      setBecause(v.because, sizeof(v.because),
                 "LoRaWAN PHY header parsed with no sync byte available; a LoRaWAN frame on "
                 "a community frequency is somebody's infrastructure, not a mesh node");
      v.reason = Reason::FullyDecoded;
      v.provenance = attribute(DecoderId::LoRaWanPhy, Reason::FullyDecoded);
      return v;
    }
  }

  // --- Signal 4: the carrier, or nothing at all ------------------------------

  //
  // A *real* sync byte that names nothing in the registry is a different finding
  // from "no evidence at all": the modulation is known and the sender is simply not
  // in our table. On a shared band that is the expected outcome for every community
  // that is not us, and folding it in with "no evidence" would bury it.
  if (haveSync) {
    v.protocol = Protocol::Unknown;
    v.basis = Basis::CarrierOnly;
    addEvidenceHex(&v, EvidenceKind::SyncWord, "unknown sync", in.link.syncWord);
    // Fits `because` with room to spare. The sentence explains the verdict and stops;
    // the longer reasoning lives in docs/ATTRIBUTION.md, where it can be read properly
    // rather than scrolled past on a serial console. Clang's -Wformat-truncation
    // enforces this, and the gate now asks GCC for the same warning.
    char text[128];
    std::snprintf(text, sizeof(text),
                  "sync word 0x%02X belongs to no network here and the body matched "
                  "nothing: most likely another community",
                  static_cast<unsigned>(in.link.syncWord));
    setBecause(v.because, sizeof(v.because), text);
    v.reason = Reason::ForeignSyncWord;
    v.provenance = attribute(DecoderId::None, Reason::ForeignSyncWord);
    return v;
  }

  // Whether the carrier was even recognised is still worth reporting: it tells the
  // operator whether to go looking for a decoder for this protocol, or for a plan
  // registry entry for this band.
  Network candidates[8];
  if (candidatesFor(in.listenPlan, candidates, 8) > 0) {
    v.protocol = Protocol::Unknown;
    v.basis = Basis::CarrierOnly;
    addEvidenceText(&v, EvidenceKind::CarrierOnly, "carrier matched a known plan");
    setBecause(v.because, sizeof(v.because),
               "no usable sync byte and nothing conclusive in the bytes; the carrier is known "
               "but nothing else is");
    v.reason = in.length <= 2 ? Reason::NoiseOrTooShort : Reason::NoEvidenceAtAll;
  } else {
    v.protocol = Protocol::Unknown;
    v.basis = Basis::Nothing;
    setBecause(v.because, sizeof(v.because),
               "nothing recognised this frame, and no known network uses this modulation");
    v.reason = in.length <= 2 ? Reason::NoiseOrTooShort : Reason::ForeignSyncWord;
  }

  v.provenance = attribute(DecoderId::None, v.reason);
  return v;
}

}  // namespace sniff
