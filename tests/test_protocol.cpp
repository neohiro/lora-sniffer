// SPDX-License-Identifier: MIT

#include <cstring>
#include <string>

#include "harness.hpp"
#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"

using namespace sniff;

namespace {

bool isReason(Reason r, const char* name) { return std::strcmp(reasonName(r), name) == 0; }

}  // namespace

void suite_protocol() {
  harness::suite("Protocol");

  CHECK(std::strcmp(protocolTag(Protocol::MeshCore), "MC") == 0);
  CHECK(std::strcmp(protocolTag(Protocol::Meshtastic), "MT") == 0);
  CHECK(std::strcmp(protocolTag(Protocol::Reticulum), "RT") == 0);
  CHECK(std::strcmp(protocolTag(Protocol::LoRaWan), "LW") == 0);
  CHECK(std::strcmp(protocolTag(Protocol::Unknown), "??") == 0);
  CHECK(std::strcmp(protocolTag(Protocol::Custom), "CX") == 0);

  CHECK(std::strcmp(protocolName(Protocol::LoRaWan), "LoRaWAN") == 0);
  CHECK(std::strcmp(protocolName(Protocol::Unknown), "Unknown") == 0);

  {
    Protocol p = Protocol::Unknown;
    CHECK(parseProtocol("meshcore", &p));
    CHECK(p == Protocol::MeshCore);
    CHECK(parseProtocol("MeshCore", &p));
    CHECK(p == Protocol::MeshCore);
    CHECK(parseProtocol("MC", &p));
    CHECK(p == Protocol::MeshCore);
    CHECK(parseProtocol("mt", &p));
    CHECK(p == Protocol::Meshtastic);
    CHECK(parseProtocol("LoRaWAN", &p));
    CHECK(p == Protocol::LoRaWan);
    CHECK(parseProtocol("lorawan", &p));
    CHECK(p == Protocol::LoRaWan);

    // A near miss must be refused, not rounded into a match. A filter that
    // accepted "meshcoree" would show a confident empty result.
    CHECK(!parseProtocol("meshcoree", &p));
    CHECK(!parseProtocol("", &p));
    CHECK(!parseProtocol(nullptr, &p));
    CHECK(!parseProtocol("meshcore", nullptr));
  }

  // Every enumerator must round-trip through its own name. This is the test that
  // catches somebody adding a protocol to the enum and forgetting the switch.
  for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(Protocol::Custom); ++i) {
    const Protocol p = static_cast<Protocol>(i);
    Protocol back = Protocol::Unknown;
    CHECK_MSG(parseProtocol(protocolName(p), &back) && back == p,
              "protocol name must round-trip through parseProtocol");
    if (p != Protocol::Unknown) {
      // "??" is Unknown's tag on purpose -- it is what an unidentified frame wears --
      // so it is the one enumerator exempt from the "needs a real tag" rule.
      CHECK_MSG(std::strcmp(protocolTag(p), "??") != 0, "every named protocol needs a real tag");
    }
  }
}

void suite_provenance() {
  harness::suite("Provenance");

  // --- decoder registry ----------------------------------------------------

  CHECK(std::strcmp(decoderIdName(DecoderId::MeshCoreV1), "meshcore.v1") == 0);
  CHECK(std::strcmp(decoderIdName(DecoderId::MeshtasticHeader), "meshtastic.meshheader") == 0);
  CHECK(std::strcmp(decoderIdName(DecoderId::None), "none") == 0);

  // These strings appear verbatim in the capture stream and in saved reports. They
  // are a contract, so they are pinned here rather than left to drift.
  CHECK_MSG(std::strcmp(decoderIdName(DecoderId::MeshCoreAdvert), "meshcore.advert") == 0,
            "decoder ids are part of the capture format contract");
  CHECK(std::strcmp(decoderIdName(DecoderId::MeshCoreGroupText), "meshcore.grp_txt") == 0);
  CHECK(std::strcmp(decoderIdName(DecoderId::LoRaWanPhy), "lorawan.phy") == 0);
  CHECK(std::strcmp(decoderIdName(DecoderId::MeshtasticData), "meshtastic.data") == 0);

  CHECK(owningDecoder(Protocol::MeshCore) == DecoderId::MeshCoreV1);
  CHECK(owningDecoder(Protocol::Meshtastic) == DecoderId::MeshtasticHeader);
  CHECK(owningDecoder(Protocol::LoRaWan) == DecoderId::LoRaWanPhy);
  // Honest rather than aspirational: no RNode header decoder is vendored here, so
  // claiming one would put a name in the capture that resolves to nothing.
  CHECK_MSG(owningDecoder(Protocol::Reticulum) == DecoderId::None,
            "Reticulum must not claim a decoder this firmware does not have");
  CHECK(owningDecoder(Protocol::Unknown) == DecoderId::None);

  // --- attribution states --------------------------------------------------

  CHECK(std::strcmp(attributionName(Attribution::Attributed), "attributed") == 0);
  CHECK(std::strcmp(attributionName(Attribution::Partial), "partial") == 0);
  CHECK(std::strcmp(attributionName(Attribution::Unattributed), "unattributed") == 0);

  // --- reason taxonomy -----------------------------------------------------

  // Every reason has a unique name. Two reasons sharing a name would make the
  // capture format ambiguous and the host filter unable to select between them.
  for (std::uint8_t i = 0; i < kReasonCount; ++i) {
    const Reason a = static_cast<Reason>(i);
    for (std::uint8_t j = static_cast<std::uint8_t>(i + 1); j < kReasonCount; ++j) {
      const Reason b = static_cast<Reason>(j);
      CHECK_MSG(std::strcmp(reasonName(a), reasonName(b)) != 0,
                "two Reason values share a name; the capture format cannot express both");
    }
  }

  // Every reason has a non-empty explanation. A blank one would print an empty
  // column in the triage table, which is worse than no column.
  for (std::uint8_t i = 0; i < kReasonCount; ++i) {
    const Reason r = static_cast<Reason>(i);
    CHECK_MSG(reasonDetail(r)[0] != '\0', "every reason needs a human explanation");
    CHECK_MSG(reasonName(r)[0] != '\0', "every reason needs a name");
  }

  CHECK(isReason(Reason::FullyDecoded, "fully-decoded"));
  CHECK(isReason(Reason::EncryptedNoKey, "encrypted-no-key"));
  CHECK(isReason(Reason::ForeignSyncWord, "foreign-sync-word"));
  CHECK(isReason(Reason::NoEvidenceAtAll, "no-evidence-at-all"));
  CHECK(isReason(Reason::KnownSyncUnknownBody, "known-sync-unknown-body"));
  CHECK(isReason(Reason::AnonymousButStructured, "anonymous-but-structured"));

  // --- the untraceable set -------------------------------------------------
  //
  // This is the boundary the brief asks for and the easiest one to get wrong. A
  // frame that was recognised and then found encrypted is *traceable* -- the
  // sniffer put a name to it and knows exactly why it cannot read further. Folding
  // it in with the genuinely-unknown frames would bury the interesting half under
  // a flood of frames that are behaving exactly as designed.

  CHECK(isUntraceable(Reason::ForeignSyncWord));
  CHECK(isUntraceable(Reason::KnownSyncUnknownBody));
  CHECK(isUntraceable(Reason::NoEvidenceAtAll));
  CHECK(isUntraceable(Reason::AnonymousButStructured));
  CHECK(isUntraceable(Reason::NoiseOrTooShort));

  CHECK_MSG(!isUntraceable(Reason::EncryptedNoKey),
            "an encrypted frame was traced to its protocol; only the key is missing");
  CHECK(!isUntraceable(Reason::MeshCoreEncrypted));
  CHECK_MSG(!isUntraceable(Reason::FullyDecoded), "a decoded frame is by definition traceable");

  // --- anomalies -----------------------------------------------------------
  //
  // Separate from untraceable: a frame that failed a structural check is a finding
  // about the air, not a gap in this firmware.

  CHECK(isAnomaly(Reason::Truncated));
  CHECK(isAnomaly(Reason::ReservedValue));
  CHECK(isAnomaly(Reason::CorruptOnAir));
  CHECK(isAnomaly(Reason::KnownSyncUnknownBody));

  CHECK_MSG(!isAnomaly(Reason::ForeignSyncWord),
            "another community on a shared band is expected, not an anomaly");
  CHECK(!isAnomaly(Reason::EncryptedNoKey));
  CHECK(!isAnomaly(Reason::NoiseOrTooShort));
  CHECK(!isAnomaly(Reason::FullyDecoded));

  // --- the three sets must not be conflated --------------------------------

  {
    // A reason may be an anomaly without being untraceable, and vice versa. If
    // these three checks ever collapse into one predicate, the triage table loses
    // its whole point.
    bool anyOverlap = false;
    for (std::uint8_t i = 0; i < kReasonCount; ++i) {
      const Reason r = static_cast<Reason>(i);
      const bool u = isUntraceable(r);
      const bool a = isAnomaly(r);
      const bool f = (r == Reason::FullyDecoded);
      if (f && (u || a)) anyOverlap = true;
    }
    CHECK_MSG(!anyOverlap, "FullyDecoded must be neither an anomaly nor untraceable");
  }

  // --- attribute() ---------------------------------------------------------

  {
    const Provenance p = attribute(DecoderId::MeshCoreV1, Reason::FullyDecoded);
    CHECK(p.attribution == Attribution::Attributed);
    CHECK(p.decoder == DecoderId::MeshCoreV1);
    CHECK(p.reason == Reason::FullyDecoded);
    CHECK_EQ(p.claimants, 1);
  }
  {
    // A protocol recognised, a key missing: partial, not unattributed.
    const Provenance p = attribute(DecoderId::MeshtasticHeader, Reason::EncryptedNoKey);
    CHECK(p.attribution == Attribution::Partial);
    CHECK_EQ(p.claimants, 1);
  }
  {
    const Provenance p = attribute(DecoderId::None, Reason::ForeignSyncWord);
    CHECK(p.attribution == Attribution::Unattributed);
    CHECK_EQ(p.claimants, 0);
  }
  {
    // No decoder and no reason to try: unattributed.
    const Provenance p = attribute(DecoderId::None, Reason::NoEvidenceAtAll);
    CHECK(p.attribution == Attribution::Unattributed);
  }
  {
    // A decoder claiming FullyDecoded but being DecoderId::None is a contradiction
    // and must resolve to unattributed rather than to a confident empty answer.
    const Provenance p = attribute(DecoderId::None, Reason::FullyDecoded);
    CHECK_MSG(p.attribution == Attribution::Unattributed,
              "no decoder cannot have fully decoded anything");
  }
}
