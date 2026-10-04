// SPDX-License-Identifier: MIT
//
// RfPlan -- what the radio was told to listen for, and what it can honestly say
// about what it heard.
//
// The distinction in this file is the one that separates a sniffer from a piece
// of firmware that lies. A receiver cannot measure the frequency, spreading
// factor or coding rate of an incoming frame. It can only demodulate at the
// parameters it was configured with, and then report a handful of per-frame
// facts: the sync byte (if the radio path exposes it), whether the header
// survived, whether the CRC survived, RSSI and SNR.
//
// So a sniffer that prints "this frame is 869.525 MHz SF11" is reporting its
// own configuration and dressing it up as an observation. The honest statement
// is "this frame arrived while I was listening on 869.525 MHz SF11/250 kHz", and
// the difference between those two sentences is the difference between a tool
// and a rumour.
//
// Everything here is therefore named for what it actually is:
//
//   RfParams       the listen plan -- what we asked the demodulator for
//   LinkEvidence   the per-frame facts the radio is willing to swear to
//   Check          three-state, because "the radio did not tell us" and
//                  "the radio told us it failed" are different facts and
//                  collapsing them is how a sniffer starts crying wolf
//
// The consequence for the operator is stated once, loudly, because it governs
// everything else in this repository: a frame sent at a spreading factor the
// sniffer is not listening at is, for most practical purposes, invisible. The
// sniffer does not see every LoRa frame in the band. It sees every frame that
// arrives at *its* demodulation settings. See docs/RF-PLAN.md.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sniff {

// ---------------------------------------------------------------------------
// The listen plan
// ---------------------------------------------------------------------------

// The modulation the demodulator is configured for. These are the settings
// written to the radio, not measurements.
struct RfParams {
  float frequencyMHz = 869.525f;
  float bandwidthKHz = 250.0f;

  // 5..12 for LoRa. Stored as the raw SF, not the register-encoded value: a
  // file called spreadingFactor = 7 must mean SF7.
  std::uint8_t spreadingFactor = 11;

  // Coding rate expressed as its denominator, so 4/5 is 5 and 4/8 is 8. Stored
  // this way because "coding rate 5" is what RadioLib and what the SX126x both
  // call it, and converting on the way in and out of the radio is the kind of
  // off-by-one that is only ever found on a rooftop.
  std::uint8_t codingRateDenominator = 5;

  std::uint8_t preambleSymbols = 8;
  bool explicitHeader = true;
  bool crcOn = true;
};

// Loose bounds, checked rather than assumed. An SF of 0 or a bandwidth of zero
// produces a plan that no radio will accept and no frame will ever match, and
// the operator deserves to hear about it at boot rather than wonder why the
// sniffer saw nothing for six hours.
bool rfParamsPlausible(const RfParams& p);

// True when two plans are the same for sniffing purposes.
//
// Frequency is compared with a tolerance because a plan is a configuration
// echoed back from a build flag or a settings file, and 869.5250 versus 869.5253
// is a rounding artefact, not two different networks.
constexpr float kFrequencyToleranceKHz = 2.0f;

bool sameRfPlan(const RfParams& a, const RfParams& b,
                float toleranceKHz = kFrequencyToleranceKHz);

// Short stable key, e.g. "869.525/250/SF11/4-5". Stable across runs and across
// firmware versions, because the host tool groups by it and a key that drifts
// between releases would silently split one network's traffic into two
// unrelated buckets in the operator's statistics.
std::string planKey(const RfParams& p);

// One-line human summary, e.g.
//   "869.525MHz 250kHz SF11 4/5 explicit crc sync-any"
std::string describeRf(const RfParams& p);

// ---------------------------------------------------------------------------
// Per-frame link evidence
// ---------------------------------------------------------------------------

// Three states, deliberately. "Not tested" is not "passed": a RadioLib
// configuration that never reads the sync-valid bit has not verified the sync
// word, it has ignored it, and reporting that as a pass would manufacture
// confidence out of a register nobody read.
enum class Check : std::uint8_t {
  Untested = 0,  // this radio path does not report it
  Passed = 1,
  Failed = 2,
};

const char* checkName(Check c);

// What the radio says about one received frame. Nothing here is inferred from
// the payload; every field comes from a register the radio is willing to
// publish.
struct LinkEvidence {
  // The sync byte, when the radio hands one over. Packet mode normally strips
  // it and reports only a match/no-match, so this is frequently unavailable --
  // and the sniffer says so rather than substituting a guess.
  std::uint8_t syncWord = 0x00;
  bool syncWordAvailable = false;

  // The preamble detector's opinion on the sync byte.
  Check syncWordCheck = Check::Untested;

  // Explicit-header CRC. Passed means the LoRa header decoded coherently, which
  // is the only in-band hint about the sender's SF/BW/CR -- and even then the
  // values themselves are not readable from the payload buffer.
  Check headerCheck = Check::Untested;

  // Payload CRC.
  Check crcCheck = Check::Untested;

  std::int16_t rssiDbm = 0;
  float snrDb = 0.0f;
};

// Frames below this are noise floor and are counted separately rather than
// being mixed into protocol statistics, so "we saw 400 MeshCore frames" cannot
// quietly become "we saw 400 frames, 380 of them thermal noise".
constexpr std::int16_t kNoiseFloorDbm = -120;

bool likelyNoise(const LinkEvidence& e);

// The strongest signal the radio gave us, for the one-line verdict.
Check strongestCheck(const LinkEvidence& e);

// Human summary of the evidence, e.g.
//   "sync 0x12 hdr ok crc bad rssi -103 snr -7.5"
std::string describeEvidence(const LinkEvidence& e);

// ---------------------------------------------------------------------------
// Sync words
// ---------------------------------------------------------------------------

// The radio reports this when promiscuous capture is on and no real preamble
// byte was matched. Carries no information, so it is never allowed to vote --
// the same rule the bridge applies, and for the same reason.
constexpr std::uint8_t kWildcardSync = 0x00;

inline bool isWildcardSync(std::uint8_t syncWord) { return syncWord == kWildcardSync; }

}  // namespace sniff
