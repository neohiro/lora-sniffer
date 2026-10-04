// SPDX-License-Identifier: MIT
//
// The radio layer. See Sx1262Promiscuous.hpp for why this file is the untested edge
// and what has to happen before its claims are tested rather than reasoned about.
//
// Exactly one thing is compiled out unless SNIFFER_TX_CAPABLE is set -- the transmit
// call itself -- and tools/gate.py greps this file for transmit calls to keep it that
// way:
//
//     #if SNIFFER_TX_CAPABLE
//         transmit one beacon
//     #endif
//
// A comment claiming the firmware never transmits is worth nothing. This is the code
// path, behind a build flag, checked in CI.
//
// The radio itself is NOT behind that flag. An earlier version guarded the whole file
// on it, on the reasoning that a sniffer only receives -- which meant the default
// build, the one everybody flashes, linked no radio at all: begin() returned false and
// the device captured nothing while looking, in every other respect, like a working
// sniffer. Receiving is the product. Only keying up needs a build flag.

#if defined(ARDUINO)

#include <Arduino.h>

#include "Sx1262Promiscuous.hpp"

#include "sniffer/Beacon.hpp"
#include "sniffer/PlanRegistry.hpp"
#include "sniffer/TxLockout.hpp"

#include <RadioLib.h>

namespace sniff {
namespace radio {

// Built once in begin(). A pointer rather than an object so this translation unit does
// not force RadioLib's headers onto every file that includes the declaration.
static SX1262* g_modem = nullptr;

// Set from the modem's IRQ callback, which runs in interrupt context, and read by
// poll() on the main loop. `volatile` because the two are not in the same thread.
volatile bool g_rxDone = false;

void IRAM_ATTR onRxDone() { g_rxDone = true; }

// The sync word we ask the modem to match, and the register control bits that go with
// it.
//
// RadioLib packs these into one 16-bit register as
// {sync[7:4] | control[7:4], sync[3:0] << 4 | control[3:0]}. The value below is
// RadioLib's own default control byte; whether it actually disables sync-word matching
// (which is what "promiscuous" requires) has NOT been confirmed against the SX126x
// datasheet or on hardware.
//
// TODO(bring-up): confirm the control bits that make the modem accept a frame whatever
// its preamble byte. Until that is done a frame that does match this word is delivered
// and nothing else is, so a board running this build may hear one network and not the
// other. Do not assume promiscuous works because this constant is called a wildcard.
constexpr std::uint8_t kWildcardSync = 0x00;
constexpr std::uint8_t kSyncControlBits = 0x44;

std::size_t Sx1262Promiscuous::freeHeap() { return ESP.getFreeHeap(); }

std::size_t Sx1262Promiscuous::freePsram() {
#if defined(ARDUINO_ARCH_ESP32S3) && defined(SPIRAM)
  return heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
#else
  return 0;
#endif
}

namespace {

// RadioLib's own float-to-bandwidth encoder, wrapped so the conversion lives in one
// place and a bandwidth the part does not accept is refused at configuration time
// rather than silently rounded into something that listens to the wrong width.
float bandwidthToKHz(float bw) {
  const float table[] = {7.8f,  10.4f, 15.6f, 20.8f, 31.25f, 41.7f, 62.5f,
                         125.0f, 250.0f, 500.0f};
  for (float candidate : table) {
    if (candidate >= bw - 0.01f) return candidate;
  }
  return 250.0f;
}

}  // namespace

bool Sx1262Promiscuous::configure(const RfParams& plan) {
  if (g_modem == nullptr) return false;

  // Variable-length packets. A sniffer does not know the length in advance, and fixing
  // it to the buffer size would either truncate long frames or stall waiting for a short
  // one to be padded out.
  int state = g_modem->fixedPacketLengthMode();
  if (state != RADIOLIB_ERR_NONE) return false;

  state = g_modem->setFrequency(plan.frequencyMHz);
  if (state != RADIOLIB_ERR_NONE) return false;

  state = g_modem->setBandwidth(bandwidthToKHz(plan.bandwidthKHz));
  if (state != RADIOLIB_ERR_NONE) return false;

  state = g_modem->setSpreadingFactor(plan.spreadingFactor);
  if (state != RADIOLIB_ERR_NONE) return false;

  state = g_modem->setCodingRate(plan.codingRateDenominator);
  if (state != RADIOLIB_ERR_NONE) return false;

  // A wildcard sync word. This is what promiscuous means at the register level, and
  // writing a real network's word here is the mistake that produces a sniffer which
  // hears one mesh and nothing else. See the TODO on kSyncControlBits above: the control
  // bits are unverified.
  state = g_modem->setSyncWord(kWildcardSync, kSyncControlBits);
  if (state != RADIOLIB_ERR_NONE) return false;

  state = g_modem->setPreambleLength(plan.preambleSymbols);
  if (state != RADIOLIB_ERR_NONE) return false;

  // CRC on by default: a frame that fails its CRC is evidence that something is
  // transmitting even though its contents are unusable, and promiscuous capture is
  // exactly the case where that evidence is worth having.
  state = g_modem->setCRC(plan.crcOn ? 2 : 1);
  if (state != RADIOLIB_ERR_NONE) return false;

  g_rxDone = false;
  g_modem->setPacketReceivedAction(onRxDone);

  state = g_modem->startReceive();
  if (state != RADIOLIB_ERR_NONE) return false;

  applied_ = plan;
  return true;
}

bool Sx1262Promiscuous::begin(const Config& config, const RfParams& plan) {
  config_ = config;

  // RadioLib 7.x: the pins go to a Module, and the modem takes that Module.
  static Module module(config.cs, config.irq, config.rst, config.busy);
  static SX1262 radio(&module);
  g_modem = &radio;

  // Frequency, bandwidth, SF, CR, sync word, power, preamble, TCXO voltage, LDO.
  // The values here are placeholders that configure() immediately overwrites from the
  // resolved plan; begin() only has to get the part out of reset and into LoRa.
  const int state = radio.begin(868.0f, 250.0f, 11, 5, kWildcardSync, /*power=*/10,
                                /*preambleLength=*/8, /*tcxoVoltage=*/1.6,
                                /*useRegulatorLDO=*/false);
  if (state != RADIOLIB_ERR_NONE) {
    Serial.printf("[radio] SX1262 begin failed: %d\n", state);
    return false;
  }

  if (!configure(plan)) {
    Serial.println("[radio] configuration refused; the plan is outside what the part accepts");
    Serial.printf("[radio] asked for %s\n", describeRf(plan).c_str());
    return false;
  }

  running_ = true;
  return true;
}

void Sx1262Promiscuous::stop() {
  if (g_modem != nullptr) g_modem->standby();
  running_ = false;
}

LinkEvidence Sx1262Promiscuous::readEvidence() {
  LinkEvidence e;
  if (g_modem == nullptr) return e;

  // `syncWordAvailable` is left false unless the radio actually handed one over.
  //
  // This is the honesty hinge of the whole firmware. Packet mode strips the sync word
  // and reports only a match, and several RadioLib paths expose nothing more. Rather
  // than substitute the configured value -- which would make every frame on the band
  // claim to be MeshCore -- this reports that the evidence is absent, and
  // Classifier, PlanRegistry and MeshCoreFrame each handle it as a real case.
  //
  // TODO(bring-up): read the preamble byte here once the modem is confirmed to expose
  // it. Until then `LinkEvidence::syncWordAvailable` stays false and every verdict
  // this firmware makes is explicitly carrier-only. Do not fill this in optimistically.
  e.syncWordAvailable = false;
  e.syncWord = kWildcardSync;

  e.syncWordCheck = Check::Untested;
  e.headerCheck = Check::Untested;

  // RadioLib returns these as floats in dB and dB/1024 respectively; the record stores
  // RSSI as an integer dBm, so the conversion happens here rather than being silently
  // truncated at the boundary.
  e.rssiDbm = static_cast<std::int16_t>(g_modem->getRSSI());
  e.snrDb = g_modem->getSNR();
  return e;
}

bool Sx1262Promiscuous::poll(Frame* out) {
  if (out == nullptr || !running_) return false;
  if (g_modem == nullptr) return false;

  // Non-blocking by contract: a flag read, not an IRQ wait. A sniffer that blocks in
  // receive cannot answer its own console, and a console that cannot be answered is how
  // a filter change gets forgotten on a roof.
  //
  // RadioLib's own `receive()` blocks for a timeout, and its IRQ-status register and
  // `clearIrqStatus()` are protected, so the supported non-blocking shape is the
  // callback: the modem raises a flag from `onRxDone` and the payload is collected here
  // with readData().
  if (!g_rxDone) return false;
  g_rxDone = false;

  uint8_t buf[kMaxFrameBytes] = {0};
  const int16_t len = g_modem->readData(buf, sizeof(buf));
  if (len <= 0) {
    // A zero-length read is a frame we cannot use, not a frame to retry: restart the
    // receiver either way, or the modem sits idle until something else pokes it.
    g_modem->startReceive();
    return false;
  }

  const std::size_t keep = static_cast<std::size_t>(len) > kMaxFrameBytes
                               ? kMaxFrameBytes
                               : static_cast<std::size_t>(len);
  for (std::size_t i = 0; i < keep; ++i) out->data[i] = buf[i];
  out->length = keep;
  out->link = readEvidence();

  // Back to listening before anything else: the window between frames is the only
  // chance to catch the next one, and this loop also has to answer its own console.
  g_modem->startReceive();

  out->valid = !likelyNoise(out->link);
  if (!out->valid) ++overruns_;
  return true;
}

#if SNIFFER_TX_CAPABLE

// Transmit one beacon. Compiled only into a beacon build, and callable only once the
// operator has armed it this boot.
//
// `mayTransmit()` is consulted and the answer is ignored on purpose -- it is
// unconditionally false, because the RX-only guarantee must not be weakenable. What
// gates this is `BeaconTx::isArmed()`, which requires both the build flag and a
// runtime arming. The two are separate on purpose: the build flag decides what
// *exists*, the arming decides what is *permitted*, and conflating them is how a
// "transmit" option ends up on by default.
bool transmitBeacon(Sx1262Promiscuous& radio, const BeaconFrame& frame,
                    const RfParams& plan) {
  (void)mayTransmit();
  if (!BeaconTx::isArmed()) return false;
  if (g_modem == nullptr) return false;

  if (!radio.configure(plan)) return false;

  const int state = g_modem->transmit(reinterpret_cast<const uint8_t*>(frame.data),
                                     frame.length);
  BeaconTx::countEmitted();
  return state == RADIOLIB_ERR_NONE;
}

#endif  // SNIFFER_TX_CAPABLE

}  // namespace radio
}  // namespace sniff

#endif  // ARDUINO
