// SPDX-License-Identifier: MIT

#include "sniffer/PlanRegistry.hpp"

#include <cstdio>
#include <cstring>

namespace sniff {
namespace {

// ---------------------------------------------------------------------------
// The known plans
// ---------------------------------------------------------------------------

// EU_868, 250 kHz, SF11, 4/5 -- the modulation that Meshtastic's EU_868 LongFast
// and MeshCore's default share exactly. On this band the two communities are
// separated by one preamble byte and nothing else.
constexpr RfParams eu868() {
  RfParams p;
  p.frequencyMHz = 869.525f;
  p.bandwidthKHz = 250.0f;
  p.spreadingFactor = 11;
  p.codingRateDenominator = 5;
  p.preambleSymbols = 8;
  p.explicitHeader = true;
  p.crcOn = true;
  return p;
}

// Included as a reference point, not a deployment recommendation. On US_915 the
// two community defaults sit 3.65 MHz apart, so a sniffer tuned to one hears
// nothing of the other -- which is a fact about the band and not about the
// sniffer, and the registry says so rather than pretending otherwise.
constexpr RfParams us915() {
  RfParams p;
  p.frequencyMHz = 910.525f;
  p.bandwidthKHz = 125.0f;
  p.spreadingFactor = 7;
  p.codingRateDenominator = 5;
  p.preambleSymbols = 8;
  p.explicitHeader = true;
  p.crcOn = true;
  return p;
}

struct NetworkEntry {
  Network network;
  const char* name;
  const char* community;
  RfParams plan;
  std::uint8_t syncWord;
  bool hasFixedSyncWord;
  Protocol protocol;
  const char* note;
};

// The load-bearing entry is the first two: they are the same plan, which is the
// entire reason this hardware can serve two meshes with one radio.
constexpr NetworkEntry kNetworks[] = {
    {Network::MeshCoreEu868, "MeshCore EU868", "MeshCore", eu868(), kMeshCoreSync, true,
     Protocol::MeshCore,
     "Group text, adverts and control frames are readable in the clear; traffic on an "
     "encrypted channel is not."},

    {Network::MeshtasticEu868LongFast, "Meshtastic EU868 LongFast", "Meshtastic", eu868(),
     kMeshtasticPublicSync, true, Protocol::Meshtastic,
     "The 16-byte header is plaintext, so sender and channel hash are readable with no key. "
     "Private channels derive their own sync word and are matched on the magic bytes instead."},

    {Network::ReticulumEu868, "Reticulum EU868", "Reticulum", eu868(), kReticulumSync, true,
     Protocol::Reticulum,
     "Sync word known, frame header not vendored here. Expect unattributable frames and read "
     "that as a gap in this firmware rather than in the network."},

    {Network::LoRaWanEu868, "LoRaWAN EU868", "LoRaWAN", us915(), kLoRaWanPublicSync, true,
     Protocol::LoRaWan,
     "Join requests carry a DevEUI in the clear. Not a mesh network: if this turns up on a "
     "community frequency, somebody's infrastructure is in the way."},
};

char lowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool equalsIgnoreCase(const char* a, const char* b) {
  if (a == nullptr || b == nullptr) return false;
  std::size_t i = 0;
  while (a[i] != '\0' && b[i] != '\0') {
    if (lowerAscii(a[i]) != lowerAscii(b[i])) return false;
    ++i;
  }
  return a[i] == '\0' && b[i] == '\0';
}

// Truncating copy into a fixed buffer. Used instead of std::string because these
// buffers travel inside a capture record that must never allocate on the device.
void setField(char* dst, std::size_t cap, const char* src) {
  if (cap == 0) return;
  std::size_t i = 0;
  for (; i + 1 < cap && src[i] != '\0'; ++i) {
    dst[i] = src[i];
  }
  dst[i] = '\0';
}

void setFormatted(char* dst, std::size_t cap, const char* fmt, unsigned value) {
  if (cap == 0) return;
  const int n = std::snprintf(dst, cap, fmt, value);
  if (n < 0) dst[0] = '\0';
}

}  // namespace

std::size_t networkCount() { return sizeof(kNetworks) / sizeof(kNetworks[0]); }

const NetworkInfo& networkAt(std::size_t index) {
  static const NetworkInfo kNone{};
  if (index >= networkCount()) return kNone;
  const NetworkEntry& e = kNetworks[index];
  static NetworkInfo cache[sizeof(kNetworks) / sizeof(kNetworks[0])];

  // Built once on first use. The indirection exists only because NetworkInfo is
  // the public shape (pointers to string literals) while the table wants
  // constexpr for the plans inside it.
  NetworkInfo& out = cache[index];
  out.network = e.network;
  out.name = e.name;
  out.community = e.community;
  out.plan = e.plan;
  out.syncWord = e.syncWord;
  out.hasFixedSyncWord = e.hasFixedSyncWord;
  out.protocol = e.protocol;
  out.note = e.note;
  return out;
}

const NetworkInfo* networkInfo(Network n) {
  for (std::size_t i = 0; i < networkCount(); ++i) {
    if (kNetworks[i].network == n) return &networkAt(i);
  }
  return nullptr;
}

bool parseNetwork(const char* text, Network* out) {
  if (text == nullptr || out == nullptr || text[0] == '\0') return false;
  for (std::size_t i = 0; i < networkCount(); ++i) {
    const NetworkInfo& info = networkAt(i);
    if (equalsIgnoreCase(text, info.name) || equalsIgnoreCase(text, info.community)) {
      *out = info.network;
      return true;
    }
  }
  return false;
}

const char* confidenceName(Confidence c) {
  switch (c) {
    case Confidence::CarrierSyncAndBody:
      return "carrier+sync+body";
    case Confidence::CarrierAndSync:
      return "carrier+sync";
    case Confidence::CarrierOnly:
    default:
      return "carrier";
  }
}

std::size_t candidatesFor(const RfParams& listenPlan, Network* out, std::size_t max) {
  if (out == nullptr) return 0;
  std::size_t n = 0;
  for (std::size_t i = 0; i < networkCount() && n < max; ++i) {
    if (sameRfPlan(kNetworks[i].plan, listenPlan)) {
      out[n] = kNetworks[i].network;
      ++n;
    }
  }
  return n;
}

PlanVerdict judge(const RfParams& listenPlan, const LinkEvidence& ev, Protocol bodyProtocol,
                  bool bodyMatched) {
  PlanVerdict v;
  v.network = Network::Unlisted;
  v.name = "unlisted network";
  v.community = "unknown";

  // Step one: does any known network use this modulation at all?
  Network candidates[8];
  const std::size_t n = candidatesFor(listenPlan, candidates, 8);
  if (n == 0) {
    setField(v.caveat, sizeof(v.caveat), "no known network uses this modulation");
    setField(v.wouldNeed, sizeof(v.wouldNeed), "a plan registry entry for this band");
    return v;
  }

  // Step two: the sync byte, when there is one. This is what separates two
  // networks that share a carrier, and it costs nothing to check.
  if (ev.syncWordAvailable && !isWildcardSync(ev.syncWord)) {
    for (std::size_t i = 0; i < n; ++i) {
      const NetworkInfo* info = networkInfo(candidates[i]);
      if (info == nullptr || !info->hasFixedSyncWord) continue;
      if (info->syncWord != ev.syncWord) continue;

      v.network = info->network;
      v.name = info->name;
      v.community = info->community;
      v.confidence = Confidence::CarrierAndSync;
      v.carrierOnly = false;

      if (bodyMatched && bodyProtocol == info->protocol) {
        v.confidence = Confidence::CarrierSyncAndBody;
      } else if (!bodyMatched) {
        setField(v.caveat, sizeof(v.caveat), "sync matched but no decoder claimed the body");
        setField(v.wouldNeed, sizeof(v.wouldNeed), "a decoder for this protocol");
      } else {
        setField(v.caveat, sizeof(v.caveat), "sync matched but the body decoded as something else");
        setField(v.wouldNeed, sizeof(v.wouldNeed), "a second opinion on the payload");
      }
      return v;
    }

    // A sync byte that belongs to no row here. On a shared band this is the
    // expected outcome for any community that is not us, and it is reported as
    // itself rather than as "unlisted plan": the modulation is known, and the
    // operator is simply outside our registry.
    setFormatted(v.caveat, sizeof(v.caveat), "sync word 0x%02X is not in the registry",
                 static_cast<unsigned>(ev.syncWord));
    setField(v.wouldNeed, sizeof(v.wouldNeed), "an entry in the plan registry for this community");
    return v;
  }

  // Step three: no usable sync byte. The carrier is all there is, which on the EU
  // band genuinely does not separate MeshCore from Meshtastic.
  if (n == 1) {
    const NetworkInfo* info = networkInfo(candidates[0]);
    if (info != nullptr) {
      v.network = info->network;
      v.name = info->name;
      v.community = info->community;
    }
  } else {
    v.network = Network::Unknown;
    v.name = "ambiguous carrier";
    v.community = "several";
  }
  v.confidence = Confidence::CarrierOnly;
  v.carrierOnly = true;
  setField(v.caveat, sizeof(v.caveat),
           ev.syncWordAvailable ? "radio reported a wildcard sync byte"
                                : "radio reported no sync byte");
  setField(v.wouldNeed, sizeof(v.wouldNeed), "promiscuous capture, so the preamble byte reaches "
                                             "the host");
  return v;
}

}  // namespace sniff
