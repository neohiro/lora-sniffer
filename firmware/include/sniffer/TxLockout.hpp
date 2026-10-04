// SPDX-License-Identifier: MIT
//
// TxLockout -- what this firmware is allowed to put on the air, and why the
// default is nothing.
//
// Two requirements pull in opposite directions, and both are legitimate:
//
//   * A **sniffer** must be silent. Putting a passive device on a community
//     frequency and having it key up is a rule problem before it is a technical
//     one, and "it only sends a keep-alive" is how that happens.
//
//   * A **beacon** is a real capability the brief asks for: send a custom message
//     to repeaters, with maximum reach, over several mesh networks, several
//     times.
//
// So the answer is two builds and one rule, rather than a compromise.
//
//   * **The default build cannot transmit.** `mayTransmit()` is `constexpr false`
//     and there is no code path that reaches a transmit register. This is the image
//     that goes on a roof next to somebody's repeater.
//
//   * **A build with `-DSNIFFER_TX_CAPABLE=1` can**, but only once the operator
//     arms it at runtime, and every beacon it emits is counted, printed and
//     included in the capture stream. Arming is a command, not a setting that
//     survives a reboot, because the state that should not survive a reboot is
//     the state in which a device is transmitting on a shared band.
//
// The beacon feature lives in Beacon.hpp and is *encode-only*: it builds frames
// and hands them to a sink. That separation is what lets the frame construction --
// the part with bugs -- be tested exhaustively on a laptop, with no radio present
// and no possibility of radiation.
//
// What this file does not do is prove the absence of an SPI write to the SX1262. A
// determined misfeature could still poke the chip directly. What it does is make
// that the only way to transmit, in a file whose entire job is to be the obvious
// place to look -- and the test suite greps the radio sources for transmit calls,
// so a future `radio.transmit(...)` fails CI rather than shipping by default.

#pragma once

#include <cstdint>

namespace sniff {

// Build flag. Absent means zero, so a build that forgets it gets the safe image.
#ifndef SNIFFER_TX_CAPABLE
#define SNIFFER_TX_CAPABLE 0
#endif

constexpr bool kBeaconBuild = (SNIFFER_TX_CAPABLE != 0);

// What the running image will do about transmission. Printed at boot and included
// in the capture stream's first line, because an operator standing next to a
// transmitting device deserves to have been told which image they flashed.
const char* txModeName();

// The guarantee for the default build, and the statement the two builds share.
constexpr const char* kRxOnlyStatement =
    "RX-only build: no transmit path is compiled in, so this device cannot key up";

constexpr const char* kBeaconStatement =
    "beacon build: transmit path compiled in but disarmed; it stays silent until armed";

// True when this image could ever transmit. Compile-time, so the beacon code is
// dead-stripped from an RX-only build rather than merely unreachable.
constexpr bool mayEverTransmit() { return kBeaconBuild; }

// The default build's guarantee. `constexpr false` regardless of build flags:
// a build that wants to transmit does so through Beacon.hopArmed(), not by
// weakening this.
constexpr bool mayTransmit() { return false; }

// True when the radio may be put into receive or standby.
constexpr bool mayReceive() { return true; }

// A guard the radio layer calls before touching a transmit-only API. Present so
// that the shape of a transmit call site has to name the thing it is asking
// permission for, and so a reviewer grepping for `transmit` finds this file.
class TxLockout {
 public:
  // Returns false always. A named, greppable, testable statement of the rule.
  static constexpr bool permit() { return mayTransmit(); }

  static constexpr bool isRxOnly() { return !permit(); }
};

// The one operation a sniffer may take that is not plain reception: keeping the
// carrier sense alive while printing. Explicitly listed so it is visibly not a
// transmission.
constexpr bool usesCarrierSense() { return true; }

// ---------------------------------------------------------------------------
// Runtime arming, for the beacon build only
// ---------------------------------------------------------------------------

// The runtime state. In the default build this compiles away entirely; in the
// beacon build it starts disarmed and nothing but `armBeacon()` changes it.
class BeaconTx {
 public:
  // Arming is deliberately not persistent. A device that comes back after a power
  // cut should be silent, and the only way to be transmitting is to have been told
  // to, this boot.
  static void armBeacon() { armed_ = true; }
  static void disarmBeacon() { armed_ = false; }
  static bool isArmed() { return armed_ && kBeaconBuild; }

  // Beacons actually emitted this boot. Part of the capture statistics, so a
  // capture file records that the sniffer was not, in fact, passive.
  static std::uint32_t emitted() { return emitted_; }
  static void countEmitted() { ++emitted_; }
  static void resetCounters() {
    armed_ = false;
    emitted_ = 0;
  }

 private:
  static bool armed_;
  static std::uint32_t emitted_;
};

}  // namespace sniff
