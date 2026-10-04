// SPDX-License-Identifier: MIT
//
// main.cpp -- on-device bring-up.
//
// Deliberately thin. Every decision this file would otherwise make -- what a frame
// means, which mesh it belongs to, whether it can be attributed, whether the operator
// wants to see it, which node it belongs to, how to say all of that -- lives in the
// portable layer, where it is compiled and tested on a laptop. What is left here is
// the part that cannot be: initialise, measure, print, poll, and answer a line typed on
// the serial console.
//
// The order below is the order of the boot log, and the order is the point:
//
//   1. serial, because nothing else can be reported otherwise
//   2. the flash and heap *as measured*, and a refusal if they are too small
//   3. the plan, and where it came from -- including the settings imported from this
//      slot, which is what makes the sniffer listen where the repeater it replaced
//      was listening
//   4. the transmit posture, in words, before anything can transmit
//   5. the radio
//   6. the loop
//
// Steps 2 and 4 come before step 5 on purpose. A device that has too little memory or
// that might transmit should say so before it starts receiving, not after.

#include <Arduino.h>
#include <SPIFFS.h>

#include <string>

#include "radio/Sx1262Promiscuous.hpp"
#include "sniffer/Beacon.hpp"
#include "sniffer/Capture.hpp"
#include "sniffer/CommandLine.hpp"
#include "sniffer/Console.hpp"
#include "sniffer/MemoryBudget.hpp"
#include "sniffer/PlanRegistry.hpp"
#include "sniffer/RfPlanSource.hpp"
#include "sniffer/SlotPlan.hpp"
#include "sniffer/Transport.hpp"
#include "sniffer/TxLockout.hpp"

// Capacities are compile-time, because the working set has to be exact and the boot
// check has to be able to compute it from sizeof. `SNIFFER_PROFILE_PSRAM` selects the
// board class; see MemoryBudget.hpp for what each one costs.
#ifndef SNIFFER_PROFILE_PSRAM
#define SNIFFER_PROFILE_PSRAM 1
#endif

#if SNIFFER_PROFILE_PSRAM
static constexpr std::size_t kDeviceCapacity = 256;
static constexpr std::size_t kRingCapacity = 256;
#else
static constexpr std::size_t kDeviceCapacity = 64;
static constexpr std::size_t kRingCapacity = 48;
#endif

#ifndef SNIFFER_REGION
#define SNIFFER_REGION "EU_868"
#endif

#ifndef FREQUENCY_MHZ
#define FREQUENCY_MHZ 0.0f
#endif

using Console = sniff::Console<kDeviceCapacity, kRingCapacity>;

namespace {

Console gConsole;
sniff::radio::Sx1262Promiscuous gRadio;

// A sink over the Arduino serial port. The only destination on a board with no phone
// attached, and the one that must never block the loop.
class SerialSink : public sniff::LineSink {
 public:
  bool putLine(const char* line, std::size_t length) override {
    Serial.write(reinterpret_cast<const uint8_t*>(line), length);
    Serial.write('\n');
    return true;
  }
  std::size_t maxLine() const override { return 512; }
};

SerialSink gSerialSink;

// The transmit sink. Only ever given frames in a beacon build that the operator has
// armed, and it counts every emission so a capture file says plainly that the device
// was not passive.
class BeaconSink : public sniff::TxSink {
 public:
  bool send(const sniff::BeaconFrame& frame) override {
    if (!sniff::BeaconTx::isArmed()) return false;
#if SNIFFER_TX_CAPABLE
    if (!sniff::radio::transmitBeacon(gRadio, frame, gConsole.lastPlan_)) return false;
    Serial.print("[tx] ");
    Serial.println(sniff::describeBeacon(frame).c_str());
    return true;
#endif
    (void)frame;
    return false;
  }
};

BeaconSink gBeaconSink;

void line(const char* text) {
  Serial.println(text);
}

// ---------------------------------------------------------------------------
// The console, over serial
// ---------------------------------------------------------------------------

// Bring the radio back after a beacon run stopped it.
bool resumeReceive() {
  sniff::radio::Config pins;
  pins.cs = 7;
  pins.irq = 13;
  pins.rst = 12;
  pins.busy = 14;
  return gRadio.begin(pins, gConsole.lastPlan_);
}

// Commands the radio or the filesystem owns. The console parses and renders; it does
// not transmit and it does not write, which is why these live here and not in
// Console.hpp -- where they would be untestable.
void handleDeferred(const sniff::Command& command, const char* verb) {
  switch (command.id) {
    case sniff::CommandId::Beacon: {
      sniff::BeaconTarget targets[2];
      std::size_t n = 0;
      if (command.beaconOnMeshCore) {
        targets[n++] = {sniff::Protocol::MeshCore, command.beaconChannel};
      }
      if (command.beaconOnMeshtastic) {
        targets[n++] = {sniff::Protocol::Meshtastic, 0x00};
      }
      if (n == 0) {
        line("beacon: no network selected");
        return;
      }

      sniff::BeaconSchedule schedule;
      schedule.count = command.beaconRepeats;
      schedule.intervalMs = command.beaconIntervalMs;

      static sniff::BeaconFrame frames[2 * sniff::kMaxBeaconRepeats];
      const sniff::BeaconPlan plan = sniff::buildBeacon(targets, n, command.arg, schedule,
                                                        frames,
                                                        sizeof(frames) / sizeof(frames[0]));
      line(plan.reason[0] == '\0' ? "beacon: plan built" : plan.reason);

      // Target-major, repeat-minor, with the operator's interval between repeats. The
      // interval is honoured here rather than in Beacon.cpp because only this layer
      // knows about the region's airtime budget -- see docs/RF-PLAN.md.
      for (std::size_t rep = 0; rep < schedule.count; ++rep) {
        for (std::size_t t = 0; t < n; ++t) {
          const std::size_t i = rep * n + t;
          if (i >= plan.built) break;
          if (!gBeaconSink.send(frames[i])) {
            line("beacon: not sent -- disarmed, or the airtime budget said no");
            gConsole.execute("emitted");
            resumeReceive();
            return;
          }
        }
        if (rep + 1 < schedule.count) {
          // Stop receiving rather than spinning: a busy wait would hold the CPU, and a
          // beacon is the one moment this device is not a listener.
          gRadio.stop();
          delay(schedule.intervalMs);
          if (!resumeReceive()) {
            line("beacon: the radio did not come back to receive; capture has stopped");
            return;
          }
        }
      }
      gConsole.execute("emitted");
      return;
    }

    case sniff::CommandId::Arm:
      sniff::BeaconTx::armBeacon();
      line(sniff::BeaconTx::isArmed()
               ? "armed: this build may transmit, and will until it reboots"
               : "this build cannot transmit at all: it was compiled with "
                 "SNIFFER_TX_CAPABLE=0");
      gConsole.execute("emitted");
      return;

    case sniff::CommandId::Disarm:
      sniff::BeaconTx::disarmBeacon();
      line("disarmed");
      gConsole.execute("emitted");
      return;

    case sniff::CommandId::Save:
      // TODO(settings): persist the console's filter and options to this slot's
      // filesystem. Refused out loud rather than silently ignored, because a `save`
      // that says nothing reads as a `save` that worked.
      line("save: not implemented yet; nothing was written");
      return;

    case sniff::CommandId::Load:
      line("load: not implemented yet; using the built-in defaults");
      return;

    case sniff::CommandId::Tail:
      line("tail: streaming is always on; this console prints every record that passes "
           "the filter");
      return;

    default:
      line(verb);
      return;
  }
}

// Read the settings this slot was provisioned with.
//
// This is what makes the sniffer usable as a stand-in for the mesh firmware it
// replaces: the MeshCore image wrote its settings into this slot's filesystem, and
// reading them means the sniffer listens where the repeater did rather than on a
// default that might be 3.65 MHz away.
//
// Read-only, and never written: a sniffer has no business rewriting a mesh stack's
// settings.
char gSettings[2048];

void loadSettings() {
  gSettings[0] = '\0';
  // SPIFFS, because that is what this slot's partition is declared as -- `fs_sniffer` is
  // a `spiffs` partition in both shipped tables, and the mount type has to match the
  // partition subtype or the ESP32 filesystem layer formats what it finds on a read-only
  // mount. This used to call LittleFS(), which is what Meshtastic's slot uses; on the
  // sniffer's own partition that mounted nothing and every boot fell back to the
  // built-in regional default, silently.
  // `false`, not `true`: the argument is format-on-mount-failure, and a sniffer that
  // formats a partition it only ever reads can destroy the settings of whatever is
  // mounted there. On a mis-paired table that is somebody else's configuration.
  if (!SPIFFS.begin(false)) {
    Serial.println("[fs] SPIFFS did not mount; using the region default");
    return;
  }
  File f = SPIFFS.open("/settings.h", FILE_READ);
  if (!f) {
    Serial.println("[fs] no settings.h in this slot; using the region default");
    return;
  }
  const size_t n = f.readBytes(gSettings, sizeof(gSettings) - 1);
  gSettings[n] = '\0';
  f.close();
  Serial.printf("[fs] read %u bytes of settings from this slot\n", static_cast<unsigned>(n));
}

void reportMemory(std::uint8_t slots) {
  sniff::Measured m;
  m.flashBytes = ESP.getFlashChipSize();
  m.slots = slots;
  m.heapFreeBytes = sniff::radio::Sx1262Promiscuous::freeHeap();
  m.psramFreeBytes = sniff::radio::Sx1262Promiscuous::freePsram();

  const sniff::MemoryProfile& profile =
      SNIFFER_PROFILE_PSRAM ? sniff::kProfilePsram : sniff::kProfileStandard;

  gConsole.memory() = sniff::checkFit(profile, m, ESP.getSketchSize());
  Serial.print(sniff::renderMemory(gConsole.memory()).c_str());

  if (!gConsole.memory().ok()) {
    Serial.println();
    Serial.println("[boot] this board is too small for the profile this build assumes.");
    Serial.println("[boot] rebuild with -DSNIFFER_PROFILE_PSRAM=0 for a board with no");
    Serial.println("[boot] PSRAM, or accept gaps in the capture and carry on.");
  }
}

// How many slots the partition table in *this* image declares.
//
// Compiled in by platformio per environment, so a running firmware says what it was
// flashed as instead of leaving the operator to guess from a filename. The default is
// the shared five-slot table; the standalone environment overrides it.
#ifndef SNIFFER_PARTITION_SLOTS
#define SNIFFER_PARTITION_SLOTS 5
#endif

std::uint8_t declaredSlots() { return static_cast<std::uint8_t>(SNIFFER_PARTITION_SLOTS); }

void boot() {
  Serial.begin(115200);
  const uint32_t t0 = millis();
  while (!Serial && millis() - t0 < 3000) {
  }

  line("");
  line("lora-sniffer");
  line("");

  // 1. What this board is, as measured rather than as assumed.
  reportMemory(declaredSlots());

  // 2. What we are listening for, and where that decision came from.
  loadSettings();

  sniff::PlanInputs inputs;
  sniff::RfParams region;
  region.frequencyMHz = 869.525f;
  region.bandwidthKHz = 250.0f;
  region.spreadingFactor = 11;
  inputs.regionPlan = region;
  inputs.overrideFrequencyMHz = FREQUENCY_MHZ;
  inputs.settingsText = gSettings[0] == '\0' ? nullptr : gSettings;

  const sniff::PlanResolution resolved = sniff::resolvePlan(inputs);
  gConsole.noteLastPlan(resolved.plan);
  Serial.printf("[plan] %s\n", sniff::describeResolution(resolved).c_str());

  sniff::Network candidates[8];
  const std::size_t n = sniff::candidatesFor(resolved.plan, candidates, 8);
  Serial.printf("[plan] %u network(s) use this modulation; a frame here is one of:\n",
                static_cast<unsigned>(n));
  for (std::size_t i = 0; i < n; ++i) {
    const sniff::NetworkInfo* info = sniff::networkInfo(candidates[i]);
    if (info == nullptr) continue;
    Serial.printf("         %s (%s) sync 0x%02X\n", info->name, info->community,
                  static_cast<unsigned>(info->syncWord));
    Serial.printf("         %s\n", info->note);
  }
  if (n > 1) {
    Serial.println("[plan] they share this modulation, so the sync byte is the only thing");
    Serial.println("[plan] that tells them apart. Promiscuous capture is what delivers it.");
  }
  Serial.println("");

  // 3. The transmit posture, in words, before anything can transmit.
  Serial.print("[tx] mode: ");
  Serial.println(sniff::txModeName());
  Serial.print("[tx] ");
  Serial.println(sniff::mayEverTransmit() ? sniff::kBeaconStatement : sniff::kRxOnlyStatement);
  Serial.println("");

  // 4. The radio.
  sniff::radio::Config pins;
  pins.cs = 7;
  pins.irq = 13;
  pins.rst = 12;
  pins.busy = 14;

  if (!gRadio.begin(pins, resolved.plan)) {
    Serial.println("[radio] the radio did not start. Nothing below this line will work,");
    Serial.println("[radio] and the console is still live so you can ask `memory` and");
    Serial.println("[radio] `plan` why. See docs/RF-PLAN.md.");
  } else {
    Serial.printf("[radio] listening on %s\n", sniff::describeRf(gRadio.appliedPlan()).c_str());
    Serial.println("[radio] sync matching relaxed; the preamble byte is read per frame");
  }
  Serial.println("");

  gConsole.addSink(&gSerialSink);
  gConsole.noteNow(millis());
  gConsole.execute("plan");

  line("");
  line("type `help` for commands. `devices` lists nodes; `stats` says where the");
  line("airtime went; `filter untraceable=true` shows only what nothing could name.");
  line("");
}

}  // namespace

// `setup` and `loop` are the Arduino task's entry points and have to be global. They
// were both inside the anonymous namespace, so `loop()` had internal linkage and the
// link failed with "undefined reference to `loop()'". Everything above stays internal.
void loop() {
  const uint32_t now = millis();
  gConsole.noteNow(now);

  sniff::radio::Frame frame;
  if (gRadio.poll(&frame)) {
    const sniff::Record& rec =
        gConsole.engine().capture(frame.data, frame.length, frame.link,
                                  gConsole.lastPlan_, now);
    gConsole.observe(rec, now);
    if (gRadio.overruns() > 0 && (now / 1000) % 30 == 0) {
      Serial.printf("[radio] %u frame(s) dropped: the air is busier than this loop drains\n",
                    static_cast<unsigned>(gRadio.overruns()));
    }
  }

  // The console. Read only when there is something to read, so a quiet band does not
  // spin on the serial port.
  while (Serial.available() > 0) {
    const int c = Serial.read();
    if (c < 0) break;
    if (c == '\r') continue;
    if (c != '\n') {
      static char lineBuf[160];
      static std::size_t used = 0;
      if (used + 1 < sizeof(lineBuf)) {
        lineBuf[used++] = static_cast<char>(c);
        lineBuf[used] = '\0';
      }
      continue;
    }

    static char lineBuf[160];
    static std::size_t used = 0;
    lineBuf[used] = '\0';

    const sniff::ParseResult parsed = sniff::parseCommand(lineBuf);
    if (!parsed.ok) {
      Serial.printf("[error] %s\n", parsed.error);
      if (parsed.suggestion[0] != '\0') Serial.printf("[error] %s\n", parsed.suggestion);
    } else if (parsed.command.id == sniff::CommandId::Arm ||
               parsed.command.id == sniff::CommandId::Disarm ||
               parsed.command.id == sniff::CommandId::Beacon ||
               parsed.command.id == sniff::CommandId::Save ||
               parsed.command.id == sniff::CommandId::Load ||
               parsed.command.id == sniff::CommandId::Tail) {
      handleDeferred(parsed.command, lineBuf);
    } else {
      gConsole.noteNow(millis());
      const sniff::ConsoleResult res = gConsole.execute(lineBuf);
      if (!res.ok) Serial.printf("[error] %s\n", res.error);
    }
    used = 0;
  }
}

void setup() { boot(); }
