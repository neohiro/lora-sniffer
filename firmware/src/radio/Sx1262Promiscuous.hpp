// SPDX-License-Identifier: MIT
//
// Sx1262Promiscuous -- the radio layer, and an honest account of what is and is not
// settled about it.
//
// This is the one file in the repository that cannot be exercised by the host gate,
// because it needs a physical SX1262. Everything above it -- classification, decoding,
// attribution, filtering, the device list, the capture format -- is testable on a
// laptop and is tested on a laptop. This file is the untested edge, and it is kept as
// small as it can be for that reason: it moves bytes and reports registers, and it
// makes no decisions that a decoder would have to trust.
//
// The enabling fact, and the thing most likely to be got wrong:
//
//   **In normal packet mode the SX1262 strips the sync word and reports only whether
//   it matched the value the radio was configured with.** A radio locked to 0x12 is
//   blind to Meshtastic; a radio locked to 0x2B is blind to MeshCore. This driver
//   therefore runs the modem in promiscuous mode -- sync matching relaxed, every frame
//   delivered -- and reads the preamble byte per frame.
//
// Whether the byte arrives intact depends on the RadioLib version and on which path
// it takes. Some configurations expose it only through a status register. This driver
// reports `syncWordAvailable = false` when it did not get one, and every module above
// is required to cope rather than to assume -- which is why `Classifier`, `PlanRegistry`
// and `MeshCoreFrame` all handle "no sync byte" as a first-class case rather than an
// error path. That is not defensive padding: on a packet-mode radio it is the *normal*
// case, and a sniffer that assumed otherwise would confidently mislabel most frames.
//
// Two things are deliberately absent:
//
//   * **No airtime accounting for transmission.** Deciding when it is legal to
//     transmit is a region question with a real answer, and this driver will not guess
//     at it from a plan that may be tuned to the wrong band. `BeaconSchedule` holds
//     what the operator asked for; whether the region's duty cycle permits it now is
//     `Airtime`'s job in the firmware that owns the radio.
//
//   * **No CAD-based channel scan.** The SX1262's channel activity detection cannot
//     distinguish one protocol's preamble from another's, so a "scan for activity then
//     switch modulation" loop would be a scan for *anybody*, not for anything useful.
//
// Verified against the SX1262 datasheet for the register map and RadioLib's SX126x
// module for the API. NOT verified against hardware. See docs/ARCHITECTURE.md for what
// has to happen before this file's claims are tested rather than merely reasoned.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Beacon.hpp"
#include "sniffer/Record.hpp"
#include "sniffer/RfPlan.hpp"

#ifndef SNIFFER_TX_CAPABLE
// Self-contained: this header is included by main.cpp, which tests the same macro, and
// a macro that is only defined in platformio.ini means the guard's value depends on
// which translation unit is asking.
#define SNIFFER_TX_CAPABLE 0
#endif

namespace sniff {
namespace radio {

// What the driver got. Deliberately the same shape the portable layer takes, so the
// handover between them copies a struct and makes no translation.
struct Frame {
  bool valid = false;

  std::uint8_t data[kMaxFrameBytes] = {};
  std::size_t length = 0;

  LinkEvidence link;

  // Set when the radio reported a header or CRC failure. Kept even though the frame
  // is unusable, because "the radio threw this away" is itself worth reporting: a
  // frame that arrived and was rejected is evidence that something is transmitting.
  bool rejected = false;
};

// The pin map and the state of the modem.
struct Config {
  int cs = 7;
  int irq = 13;
  int rst = 12;
  int busy = 14;
};

class Sx1262Promiscuous {
 public:
  Sx1262Promiscuous() = default;

  // Bring the modem up in promiscuous receive.
  //
  // Returns false rather than throwing, because a caller on a rooftop needs to be able
  // to print "the radio did not start" rather than to have the board reboot in a loop.
  bool begin(const Config& config, const RfParams& plan);

  // Poll. Returns true when a frame is available and fills `out`.
  //
  // Non-blocking. The main loop calls this and then goes and prints something else,
  // because a sniffer that blocks in receive cannot answer its console, and a console
  // that cannot be answered is how a filter change gets forgotten.
  bool poll(Frame* out);

  // Stop receiving and return the radio to standby.
  void stop();

  bool running() const { return running_; }

  // The plan the radio is actually configured for, read back from the chip.
  //
  // Read back rather than echoed, so a plan that failed to apply is visible instead of
  // being assumed. `begin()` returning true with a different plan in here is a state
  // worth reporting.
  const RfParams& appliedPlan() const { return applied_; }

  // How many frames were dropped because the radio had not finished with the previous
  // one. Non-zero means the air is busier than the loop can drain, and the operator
  // should know rather than assume they saw everything.
  std::uint32_t overruns() const { return overruns_; }

  // Free heap as the radio layer sees it, for the boot-time memory check. Measured,
  // never assumed: a datasheet figure would be a lie by the time WiFi initialises.
  static std::size_t freeHeap();
  static std::size_t freePsram();

  // Apply a plan to the modem: modulation, then the wildcard sync word, then receive.
  //
  // Public because the transmit path needs it too, and it needed it badly: the beacon
  // builder is a free function, `configure` was private, and the call had therefore
  // never been compiled -- the whole transmit path was dead on arrival.
  bool configure(const RfParams& plan);

 private:
  // Read the per-frame evidence the SX1262 will give us: sync-valid, header-valid,
  // CRC, RSSI and SNR.
  LinkEvidence readEvidence();

  Config config_{};
  RfParams applied_{};
  bool running_ = false;
  std::uint32_t overruns_ = 0;
};

#if SNIFFER_TX_CAPABLE

// Put one already-built beacon frame on the air, on `radio`.
//
// The radio is passed in rather than reached for: applying the plan and keying up both
// need the same modem, and a free function calling `configure()` unqualified -- as this
// did -- does not compile, because `configure` is a member. Nobody noticed for as long
// as no beacon env was ever built.
//
// `BeaconFrame` is included rather than forward-declared: a `struct BeaconFrame;` in
// this namespace invents a second, incomplete `sniff::radio::BeaconFrame` that no caller
// can satisfy, and Beacon.hpp is a portable header with no radio dependency anyway.
//
// Declared only for beacon builds, and callable only once the operator has armed this
// boot. `main.cpp` guards its call with the same macro.
bool transmitBeacon(Sx1262Promiscuous& radio, const BeaconFrame& frame,
                    const RfParams& plan);

#endif  // SNIFFER_TX_CAPABLE

}  // namespace radio
}  // namespace sniff
