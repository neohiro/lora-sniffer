// SPDX-License-Identifier: MIT
//
// Counters -- the summary an operator reads after an hour of listening.
//
// A sniffer that only streams frames is useful for five minutes. What makes one
// useful overnight is the aggregate: which protocol is loudest, how much of the
// band is somebody else's, and above all the ratio of frames that could be named
// to frames that could not.
//
// That ratio is the headline number and it is reported as a ratio rather than as
// two counts, because "380 of 400 frames were unattributable" and "400 frames, 20
// unattributed" are not equally legible at 2am on an OLED. `untraceableRatio()`
// returns a value in [0, 1] and the renderers print it as a percentage.
//
// Three deliberate exclusions, each of which would otherwise quietly inflate the
// numbers:
//
//   * **Noise is counted separately.** Frames below the floor, or rejected at the
//     preamble, are counted and never fed into protocol or attribution totals.
//     Mixing them in makes "we heard 400 MeshCore frames" mean something entirely
//     different from what it appears to mean.
//   * **Filtered-out frames are counted too**, in their own total. An operator
//     who sees 1000 frames and 4 records needs to be able to say "996 were
//     filtered" without going back to the firmware. `Report` carries it.
//   * **Corrupt frames are counted, and attributed to no protocol.** A frame the
//     radio reported a CRC failure on is still a real frame somebody spent airtime
//     on, but nothing decoded from it should be counted as knowledge.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Record.hpp"

namespace sniff {

constexpr std::size_t kProtocolSlots = 6;
constexpr std::size_t kNetworkSlots = 6;
constexpr std::size_t kAttributionSlots = 3;

// Number of Reason enumerators, taken from Provenance.hpp rather than written
// down here. The static assertion below is what makes adding a Reason a compile
// error in the wrong direction rather than a silent overflow at 3am.
constexpr std::size_t kReasonSlots = sniff::kReasonCount;

static_assert(static_cast<std::size_t>(Reason::NoiseOrTooShort) < kReasonSlots,
              "kReasonSlots is stale: Provenance.hpp gained a Reason");

constexpr std::size_t kMaxReasonName = 24;

// How often the rate window rolls. Short enough to be responsive when somebody
// switches channel, long enough that a single burst does not dominate.
constexpr std::uint32_t kRateWindowMs = 10000;

struct Counters {
  std::uint32_t total = 0;
  std::uint32_t passed = 0;    // matched the filter
  std::uint32_t rejected = 0;  // did not match the filter
  std::uint32_t noise = 0;
  std::uint32_t corrupt = 0;

  std::uint32_t byProtocol[kProtocolSlots] = {};
  std::uint32_t byNetwork[kNetworkSlots] = {};
  std::uint32_t byAttribution[kAttributionSlots] = {};
  std::uint32_t byReason[kReasonSlots] = {};

  // Verdicts resting on the carrier alone. A high count here means the radio was
  // not in promiscuous mode and nothing can be told apart; it is the one number
  // that tells an operator their setup is wrong rather than their band is quiet.
  std::uint32_t carrierOnly = 0;
  std::uint32_t corroborated = 0;
  std::uint32_t untraceable = 0;
  std::uint32_t anomalies = 0;

  // Rate window.
  std::uint32_t windowStartMs = 0;
  std::uint32_t windowFrames = 0;
  float framesPerMinute = 0.0f;

  void reset();
  void observe(const Record& r);
  void rollWindow(std::uint32_t nowMs);

  // Frames that reached the totals, i.e. excluding noise. This is the denominator
  // for every ratio here: a percentage of "everything the radio reported" would
  // move every time the noise did.
  std::uint32_t analysed() const { return total - noise; }

  // In [0, 1]. Returns 0 when nothing has been analysed rather than dividing by
  // zero; a sniffer that reports 0% unattributable before it has heard anything
  // is claiming a result it does not have.
  float untraceableRatio() const;

  // Count for one reason.
  std::uint32_t reasonCount(Reason r) const;
};

// The rendered summary. Multi-line and fixed-format so it diffs cleanly between
// two captures, which is how "did the untraceable ratio go up when I changed
// channel" is answered.
std::string renderCounters(const Counters& c);

}  // namespace sniff
