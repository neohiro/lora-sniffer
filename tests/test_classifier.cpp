// SPDX-License-Identifier: MIT
//
// Classification, and the network verdict that sits on top of it.
//
// The precedence rules are the fragile part of this whole project, so they are
// tested as a table: for each combination of (sync byte present, sync byte value,
// magic present) the verdict must be exactly one specific thing. A rule change
// that quietly reorders precedence shows up here rather than in a field.

#include <cstring>
#include <vector>

#include "harness.hpp"
#include "sniffer/Classifier.hpp"
#include "sniffer/LoRaWanFrame.hpp"
#include "sniffer/MeshtasticFrame.hpp"
#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/PlanRegistry.hpp"

using namespace sniff;
using namespace sniff::meshtastic;

namespace {

RfParams eu868() {
  RfParams p;
  p.frequencyMHz = 869.525f;
  p.bandwidthKHz = 250.0f;
  p.spreadingFactor = 11;
  return p;
}

RfParams us915() {
  RfParams p;
  p.frequencyMHz = 910.525f;
  p.bandwidthKHz = 125.0f;
  p.spreadingFactor = 7;
  return p;
}

LinkEvidence linkWith(bool haveSync, std::uint8_t sync) {
  LinkEvidence e;
  e.rssiDbm = -100;
  e.snrDb = -8.0f;
  e.crcCheck = Check::Passed;
  e.syncWordAvailable = haveSync;
  e.syncWord = sync;
  e.syncWordCheck = haveSync ? Check::Passed : Check::Untested;
  return e;
}

Input make(const std::vector<std::uint8_t>& d, const LinkEvidence& e, const RfParams& p) {
  Input in;
  in.data = d.data();
  in.length = d.size();
  in.link = e;
  in.listenPlan = p;
  return in;
}

// A well-formed MeshCore GRP_TXT frame, header + zero-hop path + a small payload.
std::vector<std::uint8_t> meshcoreGroupText() {
  // header: v1, GrpTxt, Flood -> (0<<6)|(5<<2)|1
  return std::vector<std::uint8_t>{0x15, 0x00, 0x01, 0x8F, 'h', 'i'};
}

std::vector<std::uint8_t> meshtasticHeaderOnly(std::uint8_t channelHash) {
  return std::vector<std::uint8_t>{kMagic0, kMagic1, kMagic2, 0xFF, 0x01, 0x02, 0x03, 0x04,
                                  0x05,   0x06,   0x07,   0x08,   0x14, channelHash, 0x00,
                                  0x00,   0x01};
}

std::vector<std::uint8_t> loRaWanUplink() {
  std::vector<std::uint8_t> v(20, 0);
  v[0] = 0x40;  // unconfirmed data up, major 0
  v[1] = 0xEF;
  v[2] = 0xBE;
  v[3] = 0xAD;
  v[4] = 0xDE;
  v[5] = 0x80;
  v[6] = 0x07;
  v[7] = 0x00;
  v[8] = 0x01;
  return v;
}

std::vector<std::uint8_t> pureNoise() {
  return std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33};
}

bool hasEvidence(const Verdict& v, EvidenceKind k) {
  for (std::size_t i = 0; i < v.evidenceCount; ++i) {
    if (v.evidence[i].kind == k) return true;
  }
  return false;
}

}  // namespace

void suite_classifier() {
  harness::suite("Classifier");

  // --- the happy paths -----------------------------------------------------

  {
    const Verdict v =
        classify(make(meshcoreGroupText(), linkWith(true, kMeshCoreSync), eu868()));
    CHECK(v.protocol == Protocol::MeshCore);
    CHECK(v.basis == Basis::SyncOnly);
    CHECK_MSG(!v.corroborated, "one signal is not corroborated, and the operator is told so");
    CHECK(!v.syncUnavailable);
    CHECK(hasEvidence(v, EvidenceKind::SyncWord));
    CHECK(v.reason == Reason::FullyDecoded);
    CHECK(std::strstr(v.because, "sync word") != nullptr);
  }
  {
    const Verdict v =
        classify(make(meshtasticHeaderOnly(0x8F), linkWith(true, kMeshtasticPublicSync), eu868()));
    CHECK(v.protocol == Protocol::Meshtastic);
    CHECK_MSG(v.basis == Basis::SyncAndMagic, "sync and magic agreeing is the strongest cheap path");
    CHECK(v.corroborated);
    CHECK(hasEvidence(v, EvidenceKind::SyncWord));
    CHECK(hasEvidence(v, EvidenceKind::MeshHeaderMagic));
  }

  // --- private channels: the reason the magic exists ------------------------

  {
    // A Meshtastic private channel derives its sync word from the channel hash, so
    // it arrives wearing a byte no table here has seen. The magic is the only
    // thing that saves it -- and a sync-word-only design would drop it entirely.
    const Verdict v =
        classify(make(meshtasticHeaderOnly(0x77), linkWith(true, 0x77), eu868()));
    CHECK(v.protocol == Protocol::Meshtastic);
    CHECK(v.basis == Basis::MagicOnly);
    CHECK_MSG(!v.corroborated, "one signal");
    CHECK(std::strstr(v.because, "private channel") != nullptr);
  }
  {
    // No sync byte at all and a magic present: still Meshtastic.
    const Verdict v = classify(make(meshtasticHeaderOnly(0x42), linkWith(false, 0), eu868()));
    CHECK(v.protocol == Protocol::Meshtastic);
    CHECK(v.basis == Basis::MagicOnly);
    CHECK(v.syncUnavailable);
  }

  // --- the contradiction rule ----------------------------------------------

  {
    // MeshCore sync word, Meshtastic magic. The bridge's rule: the in-band magic
    // wins, because it was read from the same buffer as the payload and the
    // preamble may be corrupt.
    const Verdict v =
        classify(make(meshtasticHeaderOnly(0x8F), linkWith(true, kMeshCoreSync), eu868()));
    CHECK(v.protocol == Protocol::Meshtastic);
    CHECK_MSG(v.basis == Basis::MagicOverrodeSync,
              "a sync byte naming one mesh and a magic naming another is a corrupt capture");
    CHECK_MSG(std::strstr(v.because, "corrupt capture") != nullptr,
              "and the reason for the override is stated");
  }

  // --- Reticulum: honest, not aspirational ---------------------------------

  {
    const std::vector<std::uint8_t> body = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    const Verdict v = classify(make(body, linkWith(true, kReticulumSync), eu868()));
    CHECK(v.protocol == Protocol::Reticulum);
    CHECK(v.basis == Basis::SyncOnly);
    CHECK_MSG(v.provenance.decoder == DecoderId::None,
              "no RNode header decoder is vendored, so no decoder may be claimed");
    CHECK(v.reason == Reason::KnownSyncUnknownBody);
    CHECK_MSG(v.provenance.attribution == Attribution::Unattributed,
              "nothing could read it, so it belongs in the untraceable bucket");
    CHECK(std::strstr(v.because, "no RNode header decoder") != nullptr);
  }

  // --- the wildcard --------------------------------------------------------

  {
    // 0x00 delivered as a real byte carries no information and must not vote.
    const std::vector<std::uint8_t> body = pureNoise();
    const Verdict v = classify(make(body, linkWith(true, 0x00), eu868()));
    CHECK_MSG(v.protocol == Protocol::Unknown, "a wildcard sync byte cannot name a protocol");
    CHECK(v.syncUnavailable);
    CHECK_MSG(hasEvidence(v, EvidenceKind::None), "the wildcard is recorded");
    CHECK_MSG(std::strstr(v.because, "nothing conclusive") != nullptr, "the wildcard case says the carrier is all there is");
  }

  // --- structural fallbacks -------------------------------------------------
  //
  // Only reached when the radio stripped the preamble, which is the common case in
  // packet mode. These are guesses with good odds and are labelled as such.

  {
    const Verdict v = classify(make(meshcoreGroupText(), linkWith(false, 0), eu868()));
    CHECK(v.protocol == Protocol::MeshCore);
    CHECK(v.basis == Basis::StructureOnly);
    CHECK(hasEvidence(v, EvidenceKind::MeshCoreHeader));
    CHECK_MSG(std::strstr(v.because, "not identification") != nullptr ||
                  std::strstr(v.because, "structure") != nullptr,
              "a structural read must be labelled as structure, not as identification");
  }
  {
    const Verdict v = classify(make(loRaWanUplink(), linkWith(false, 0), eu868()));
    CHECK(v.protocol == Protocol::LoRaWan);
    CHECK(v.basis == Basis::StructureOnly);
    CHECK_MSG(std::strstr(v.because, "infrastructure") != nullptr,
              "a LoRaWAN frame on a mesh frequency is somebody's infrastructure");
  }

  // --- unknown means unknown ------------------------------------------------
  //
  // The most important negative test in the project. On a shared band somebody
  // else's LoRa is far more likely to be arriving than ours, and defaulting to a
  // mesh is how a sniffer starts filing a foreign community's traffic under our
  // names.

  {
    const Verdict v = classify(make(pureNoise(), linkWith(true, 0x99), eu868()));
    CHECK_MSG(v.protocol == Protocol::Unknown, "an unrecognised sync word must not be guessed at");
    CHECK(v.basis == Basis::CarrierOnly);
    CHECK(v.reason == Reason::ForeignSyncWord);
    CHECK(v.provenance.attribution == Attribution::Unattributed);
    CHECK_MSG(std::strstr(v.because, "belongs to no network") != nullptr,
              "a real but unknown sync byte is its own finding, distinct from having no byte at all");
  }
  {
    // No sync byte, nothing structural, but the carrier is a known plan.
    const Verdict v = classify(make(pureNoise(), linkWith(false, 0), eu868()));
    CHECK(v.protocol == Protocol::Unknown);
    CHECK(v.basis == Basis::CarrierOnly);
    CHECK_MSG(v.reason == Reason::NoEvidenceAtAll,
              "the honest answer when there is no sync byte and nothing conclusive");
    CHECK(v.provenance.attribution == Attribution::Unattributed);
  }
  {
    // Two bytes or fewer cannot carry any structure.
    const std::vector<std::uint8_t> tiny = {0x01, 0x02};
    const Verdict v = classify(make(tiny, linkWith(false, 0), eu868()));
    CHECK(v.reason == Reason::NoiseOrTooShort);
  }
  {
    // An unlisted modulation: not even the carrier is recognised. US_915 is *not* a
    // good example here, because the LoRaWAN registry entry uses that plan -- pick a
    // band nothing in the table covers.
    RfParams nowhere;
    nowhere.frequencyMHz = 400.0f;
    nowhere.bandwidthKHz = 7.8f;
    nowhere.spreadingFactor = 12;
    const Verdict v = classify(make(pureNoise(), linkWith(false, 0), nowhere));
    CHECK(v.protocol == Protocol::Unknown);
    CHECK_MSG(v.basis == Basis::Nothing, "no known network uses this modulation");
    CHECK(std::strstr(v.because, "no known network uses this modulation") != nullptr);
  }

  // --- an empty frame is never a protocol ----------------------------------

  {
    Input in;
    in.length = 0;
    in.listenPlan = eu868();
    in.link = linkWith(false, 0);
    const Verdict v = classify(in);
    CHECK(v.protocol == Protocol::Unknown);
    CHECK(!v.corroborated);
  }

  // --- names ---------------------------------------------------------------

  CHECK(std::strcmp(evidenceKindName(EvidenceKind::SyncWord), "sync") == 0);
  CHECK(std::strcmp(evidenceKindName(EvidenceKind::MeshHeaderMagic), "magic") == 0);
  CHECK(std::strcmp(basisName(Basis::MagicOverrodeSync), "magic-over-sync") == 0);
  CHECK(std::strcmp(basisName(Basis::SyncAndMagic), "sync+magic") == 0);

  // Every basis has a distinct name. Checked for distinctness rather than "not
  // nothing", because Nothing is a legitimate value with a legitimate name and it is
  // the honest answer for a frame that matched nothing at all.
  for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(Basis::MagicOverrodeSync); ++i) {
    for (std::uint8_t j = static_cast<std::uint8_t>(i + 1);
         j <= static_cast<std::uint8_t>(Basis::MagicOverrodeSync); ++j) {
      CHECK_MSG(std::strcmp(basisName(static_cast<Basis>(i)), basisName(static_cast<Basis>(j))) != 0,
                "two bases share a name, and 'why was this labelled that' would be unanswerable");
    }
  }
  CHECK(std::strcmp(basisName(Basis::Nothing), "nothing") == 0);
}

void suite_plan_registry() {
  harness::suite("PlanRegistry");

  // --- the registry --------------------------------------------------------

  CHECK(networkCount() >= 4);
  CHECK(networkInfo(Network::MeshCoreEu868) != nullptr);
  CHECK(networkInfo(Network::MeshtasticEu868LongFast) != nullptr);
  CHECK(networkInfo(Network::ReticulumEu868) != nullptr);
  CHECK(networkInfo(Network::LoRaWanEu868) != nullptr);
  CHECK_MSG(networkInfo(Network::Unknown) == nullptr, "Unknown is not a registry entry");

  for (std::size_t i = 0; i < networkCount(); ++i) {
    const NetworkInfo& info = networkAt(i);
    CHECK_MSG(info.name != nullptr && info.name[0] != '\0', "every network needs a name");
    CHECK_MSG(info.community != nullptr && info.community[0] != '\0',
              "the community is the first question an operator asks");
    CHECK_MSG(info.note != nullptr && info.note[0] != '\0', "every network needs a note");
    CHECK_MSG(rfParamsPlausible(info.plan), "a registry entry with an impossible plan is a bug");
  }

  {
    Network n = Network::Unknown;
    CHECK(parseNetwork("meshcore", &n) && n == Network::MeshCoreEu868);
    CHECK(parseNetwork("MeshCore", &n) && n == Network::MeshCoreEu868);
    CHECK(parseNetwork("meshtastic", &n) && n == Network::MeshtasticEu868LongFast);
    CHECK(parseNetwork("LoRaWAN", &n) && n == Network::LoRaWanEu868);
    CHECK(!parseNetwork("meshcoree", &n));
    CHECK(!parseNetwork("", &n));
    CHECK(!parseNetwork(nullptr, &n));
  }

  // --- candidate lookup ----------------------------------------------------

  {
    // The finding the whole architecture rests on: on EU_868 MeshCore and
    // Meshtastic are the *same* modulation and differ by one preamble byte.
    Network out[8];
    const std::size_t n = candidatesFor(eu868(), out, 8);
    CHECK_MSG(n >= 2, "MeshCore, Meshtastic and Reticulum all share the EU_868 modulation");
    bool sawMc = false;
    bool sawMt = false;
    for (std::size_t i = 0; i < n; ++i) {
      if (out[i] == Network::MeshCoreEu868) sawMc = true;
      if (out[i] == Network::MeshtasticEu868LongFast) sawMt = true;
    }
    CHECK(sawMc);
    CHECK(sawMt);

    // US_915: the two community defaults are far apart, so a sniffer on one hears
    // nothing of the other.
    const std::size_t m = candidatesFor(us915(), out, 8);
    CHECK_MSG(m <= 1, "the US_915 defaults do not share a carrier");
  }
  {
    Network none[8];
    CHECK(candidatesFor(eu868(), nullptr, 8) == 0);
    RfParams nowhere;
    nowhere.frequencyMHz = 400.0f;
    nowhere.bandwidthKHz = 7.8f;
    nowhere.spreadingFactor = 12;
    CHECK_MSG(candidatesFor(nowhere, none, 8) == 0, "an unlisted plan has no candidates");
  }

  // --- the three confidence levels -----------------------------------------

  {
    // carrier+sync: the sync byte named the network.
    const PlanVerdict v = judge(eu868(), linkWith(true, kMeshCoreSync), Protocol::MeshCore, true);
    CHECK(v.network == Network::MeshCoreEu868);
    CHECK(v.confidence == Confidence::CarrierSyncAndBody);
    CHECK_MSG(!v.carrierOnly, "a sync match is not carrier-only");
    CHECK_MSG(v.caveat[0] == '\0', "a fully evidenced verdict states no caveat");
  }
  {
    // carrier+sync, body not claimed.
    const PlanVerdict v = judge(eu868(), linkWith(true, kMeshCoreSync), Protocol::Unknown, false);
    CHECK(v.network == Network::MeshCoreEu868);
    CHECK(v.confidence == Confidence::CarrierAndSync);
    CHECK_MSG(v.caveat[0] != '\0', "and says what is still missing");
    CHECK(std::strstr(v.caveat, "no decoder") != nullptr);
    CHECK_MSG(v.wouldNeed[0] != '\0', "and what would settle it");
  }
  {
    // carrier+sync, but the body decoded as something else entirely.
    const PlanVerdict v =
        judge(eu868(), linkWith(true, kMeshCoreSync), Protocol::Meshtastic, true);
    CHECK(v.confidence == Confidence::CarrierAndSync);
    CHECK(std::strstr(v.caveat, "something else") != nullptr);
  }
  {
    // carrier only, and ambiguous because two networks share it. This is the case
    // an operator must be able to see at a glance.
    const PlanVerdict v = judge(eu868(), linkWith(false, 0), Protocol::Unknown, false);
    CHECK_MSG(v.carrierOnly, "no sync byte means carrier-only");
    CHECK(v.confidence == Confidence::CarrierOnly);
    CHECK(v.network == Network::Unknown);
    CHECK(std::strcmp(v.name, "ambiguous carrier") == 0);
    CHECK(std::strcmp(v.caveat, "radio reported no sync byte") == 0);
    CHECK_MSG(std::strstr(v.wouldNeed, "promiscuous") != nullptr,
              "the fix for the most common misconfiguration is named");
  }
  {
    // A wildcard byte is the same as no byte for this purpose.
    const PlanVerdict v = judge(eu868(), linkWith(true, 0x00), Protocol::Unknown, false);
    CHECK(v.carrierOnly);
    CHECK(std::strcmp(v.caveat, "radio reported a wildcard sync byte") == 0);
  }
  {
    // A sync byte outside the registry: the modulation is known and the operator
    // is simply not in our table. Different from "no known network uses this".
    const PlanVerdict v = judge(eu868(), linkWith(true, 0x99), Protocol::Unknown, false);
    CHECK(v.network == Network::Unlisted);
    CHECK(std::strstr(v.caveat, "0x99") != nullptr);
    CHECK(std::strstr(v.wouldNeed, "plan registry") != nullptr);
  }
  {
    // Nothing known at all.
    RfParams nowhere;
    nowhere.frequencyMHz = 400.0f;
    nowhere.bandwidthKHz = 7.8f;
    nowhere.spreadingFactor = 12;
    const PlanVerdict v = judge(nowhere, linkWith(true, 0x12), Protocol::Unknown, false);
    CHECK(v.network == Network::Unlisted);
    CHECK(std::strstr(v.caveat, "no known network uses this modulation") != nullptr);
  }

  CHECK(std::strcmp(confidenceName(Confidence::CarrierOnly), "carrier") == 0);
  CHECK(std::strcmp(confidenceName(Confidence::CarrierAndSync), "carrier+sync") == 0);
  CHECK(std::strcmp(confidenceName(Confidence::CarrierSyncAndBody), "carrier+sync+body") == 0);
}
