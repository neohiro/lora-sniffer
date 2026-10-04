// SPDX-License-Identifier: MIT

#include "sniffer/TxLockout.hpp"

namespace sniff {

// File-scope definitions for the template-like statics. One instance per program,
// no duplicate-symbol trouble when the header lands in several translation units.
bool BeaconTx::armed_ = false;
std::uint32_t BeaconTx::emitted_ = 0;

const char* txModeName() {
  if (!kBeaconBuild) return "rx-only";
  if (BeaconTx::isArmed()) return "beacon-armed";
  return "beacon-disarmed";
}

}  // namespace sniff
