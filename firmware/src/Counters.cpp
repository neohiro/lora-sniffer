// SPDX-License-Identifier: MIT

#include "sniffer/Counters.hpp"

#include <cstdarg>
#include <cstdio>

namespace sniff {
namespace {

std::string format(const char* fmt, ...) {
  char buf[224];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  const std::size_t len = static_cast<std::size_t>(n);
  return std::string(buf, len < sizeof(buf) ? len : sizeof(buf) - 1);
}

}  // namespace

void Counters::reset() { *this = Counters{}; }

void Counters::observe(const Record& r) {
  ++total;

  // Every frame counts towards the rate, including noise and including frames the
  // filter rejected. A rate that silently excluded filtered frames would read low
  // exactly when an operator had narrowed their filter and started wondering why.
  ++windowFrames;

  if (r.noise) {
    ++noise;
    // Everything else is about knowledge, and a frame below the floor produced
    // none. Counting it as unknown would make a noisy band look like a mysterious
    // one.
    return;
  }

  if (r.corrupt) ++corrupt;

  ++byProtocol[static_cast<std::size_t>(r.protocol)];
  ++byNetwork[static_cast<std::size_t>(r.verdict.network)];
  ++byAttribution[static_cast<std::size_t>(r.provenance.attribution)];
  ++byReason[static_cast<std::size_t>(r.provenance.reason)];

  if (r.verdict.carrierOnly) ++carrierOnly;
  if (r.provenance.claimants >= 2) ++corroborated;
  if (isUntraceable(r.provenance.reason)) ++untraceable;
  if (isAnomaly(r.provenance.reason)) ++anomalies;

  if (r.filtered) {
    ++rejected;
  } else {
    ++passed;
  }
}

void Counters::rollWindow(std::uint32_t nowMs) {
  // Unsigned arithmetic, so this is correct across the millis() wrap that a
  // device left running for 49 days will hit. That is not a theoretical concern
  // for a tool whose selling point is being left running.
  const std::uint32_t elapsed = nowMs - windowStartMs;
  if (elapsed < kRateWindowMs) return;

  // Fractional windows are handled by scaling rather than by rounding the window
  // down, so a rate computed from two windows is the average of two windows and
  // not the average of the first plus a spike.
  framesPerMinute = (static_cast<float>(windowFrames) * 60000.0f) / static_cast<float>(elapsed);
  windowStartMs = nowMs;
  windowFrames = 0;
}

float Counters::untraceableRatio() const {
  const std::uint32_t denom = analysed();
  if (denom == 0) return 0.0f;
  return static_cast<float>(untraceable) / static_cast<float>(denom);
}

std::uint32_t Counters::reasonCount(Reason r) const {
  const std::size_t i = static_cast<std::size_t>(r);
  if (i >= kReasonSlots) return 0;
  return byReason[i];
}

std::string renderCounters(const Counters& c) {
  std::string s;

  s += format("frames      %u total, %u analysed, %u noise\n", static_cast<unsigned>(c.total),
              static_cast<unsigned>(c.analysed()), static_cast<unsigned>(c.noise));
  s += format("            %u shown, %u filtered out, %u corrupt\n",
              static_cast<unsigned>(c.passed), static_cast<unsigned>(c.rejected),
              static_cast<unsigned>(c.corrupt));
  s += format("rate        %.1f frames/min\n", static_cast<double>(c.framesPerMinute));

  s += format("attributed  %u attributed, %u partial, %u unattributed (%.0f%% untraceable)\n",
              static_cast<unsigned>(c.byAttribution[static_cast<std::size_t>(Attribution::Attributed)]),
              static_cast<unsigned>(c.byAttribution[static_cast<std::size_t>(Attribution::Partial)]),
              static_cast<unsigned>(c.byAttribution[static_cast<std::size_t>(
                  Attribution::Unattributed)]),
              static_cast<double>(c.untraceableRatio() * 100.0f));

  s += format("protocol    ");
  for (std::size_t i = 0; i < kProtocolSlots; ++i) {
    if (c.byProtocol[i] == 0) continue;
    s += format("%s=%u ", protocolTag(static_cast<Protocol>(i)),
                static_cast<unsigned>(c.byProtocol[i]));
  }
  s += "\n";

  s += format("network     ");
  for (std::size_t i = 0; i < kNetworkSlots; ++i) {
    if (c.byNetwork[i] == 0) continue;
    const NetworkInfo* info = networkInfo(static_cast<Network>(i));
    s += format("%s=%u ", info != nullptr ? info->community : "?", static_cast<unsigned>(c.byNetwork[i]));
  }
  s += "\n";

  // The reason breakdown is the whole point of the module, so it is printed in
  // full rather than only the non-zero leading entries: a reason that dropped to
  // zero between two runs is exactly what an operator comparing two captures is
  // looking for.
  s += "reasons\n";
  for (std::size_t i = 0; i < kReasonSlots; ++i) {
    const Reason r = static_cast<Reason>(i);
    const std::uint32_t n = c.byReason[i];
    if (n == 0) continue;
    s += format("  %-24s %6u  %s\n", reasonName(r), static_cast<unsigned>(n), reasonDetail(r));
  }

  s += format("evidence    %u resting on carrier only, %u with two agreeing signals, "
              "%u anomalies\n",
              static_cast<unsigned>(c.carrierOnly), static_cast<unsigned>(c.corroborated),
              static_cast<unsigned>(c.anomalies));

  if (c.carrierOnly > 0 && c.total > 0) {
    s += "note        a high carrier-only count means the radio is not in promiscuous\n"
         "            mode: the preamble byte is being stripped, so nothing can be\n"
         "            told apart even when the body would decode. See docs/RF-PLAN.md\n";
  }
  return s;
}

}  // namespace sniff
