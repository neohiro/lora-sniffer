// SPDX-License-Identifier: MIT
//
// PlanRegistry -- "which network could this have been on?"
//
// The sniffer listens on exactly one modulation at a time, so the honest answer
// to that question has three levels, and this module refuses to collapse them:
//
//   carrier       The frame arrived on a modulation only this network uses.
//                 Useful, and still not a claim about the frame's contents. On
//                 EU_868 that means "this is either MeshCore or Meshtastic",
//                 because those two genuinely share a carrier.
//
//   carrier+sync  The radio also handed over a sync byte and it matched this
//                 network's. That is a real identification and needs no
//                 decryption, which is why promiscuous capture is worth its
//                 cost.
//
//   carrier+sync+body
//                 The bytes then parsed as this protocol's own structures. The
//                 only level at which "this is a MeshCore ADVERT" is a
//                 statement about content rather than about a preamble.
//
// The `carrierOnly` flag on the result is the important one. An operator reading
// a capture where every frame is labelled `carrier` should be able to see, in
// one glance, that the sniffer was not given a sync byte -- because on a
// packet-mode radio it never will be, and a sniffer that quietly assumed it had
// would be filing frames under networks it had no evidence for.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Protocol.hpp"
#include "sniffer/RfPlan.hpp"

namespace sniff {

// Networks this build can name. `Unlisted` is not a failure state -- it is what a
// frame from a plan nobody here has a row for is called, and naming it that way
// keeps the distinction between "I do not know" and "I know it is not one of
// mine".
enum class Network : std::uint8_t {
  Unknown = 0,
  MeshCoreEu868,
  MeshtasticEu868LongFast,
  ReticulumEu868,
  LoRaWanEu868,
  Unlisted,
};

struct NetworkInfo {
  Network network = Network::Unknown;
  const char* name = "";

  // Who runs it, in one word. An operator's first question about an unfamiliar
  // frame is "whose is this", and this is the field that answers it.
  const char* community = "";

  RfParams plan;

  // The sync word this network uses, or 0 when it has none fixed. Meshtastic
  // private channels derive theirs from the channel hash, so no single byte
  // describes them -- which is why the magic bytes matter and why
  // `syncWord == 0` here is a fact rather than a missing value.
  std::uint8_t syncWord = 0x00;
  bool hasFixedSyncWord = false;

  Protocol protocol = Protocol::Unknown;

  // One line on what a capture of this network actually contains.
  const char* note = "";
};

const NetworkInfo* networkInfo(Network n);
const NetworkInfo& networkAt(std::size_t index);
std::size_t networkCount();

// Look up by name or by tag, case-insensitive. Returns false rather than
// defaulting, for the same reason parseProtocol does.
bool parseNetwork(const char* text, Network* out);

// How well the evidence supports naming a network.
enum class Confidence : std::uint8_t {
  CarrierOnly = 0,
  CarrierAndSync = 1,
  CarrierSyncAndBody = 2,
};

const char* confidenceName(Confidence c);

// Small enough to live on the stack beside a capture record, which is what lets
// `judge()` return by value on the device without touching the heap.
constexpr std::size_t kCaveatBytes = 72;

struct PlanVerdict {
  Network network = Network::Unknown;
  const char* name = "";
  const char* community = "";
  Confidence confidence = Confidence::CarrierOnly;

  // True whenever the verdict rests on the carrier alone. Named rather than
  // folded into the confidence enum because this is the flag an operator has to
  // be warned about, and a flag is impossible to read past.
  bool carrierOnly = true;

  // The specific reason this verdict and not a stronger one, e.g.
  // "radio reported no sync byte". Empty when the verdict is fully evidenced.
  //
  // A fixed buffer rather than a `const char*`: these are computed per frame,
  // and a pointer into a local std::string would outlive it. This is a bug class
  // that shows up once a week and once a week is too often.
  char caveat[kCaveatBytes] = {};

  // The next piece of evidence that would settle it. Shown to the operator
  // because "why can't this tool be sure" is more useful than "it wasn't sure".
  char wouldNeed[kCaveatBytes] = {};
};

// Judge one received frame against the listen plan.
//
// `bodyMatched` is what the protocol decoder concluded. Passing it is how a
// caller escalates from carrier+sync to carrier+sync+body, and it is a separate
// argument on purpose: the classifier decides it, and the registry must not infer
// content from a preamble.
PlanVerdict judge(const RfParams& listenPlan, const LinkEvidence& ev,
                  Protocol bodyProtocol, bool bodyMatched);

// Every network whose plan matches the listen plan, whether or not anything was
// decoded. Used by the operator's "who else could this be" answer, which is
// frequently the interesting one.
std::size_t candidatesFor(const RfParams& listenPlan, Network* out, std::size_t max);

}  // namespace sniff
