// SPDX-License-Identifier: MIT

#include "sniffer/RfPlan.hpp"

#include <cmath>
#include <cstdarg>
#include <cstdio>

namespace sniff {
namespace {

// Shared by the string builders below. snprintf on ESP32 Arduino and on a host
// both honour the size argument, so one helper is enough and no std::to_string
// is needed anywhere in the capture path.
std::string format(const char* fmt, ...) {
  char buf[192];
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  if (n < 0) return std::string();
  return std::string(buf, static_cast<std::size_t>(n) < sizeof(buf)
                              ? static_cast<std::size_t>(n)
                              : sizeof(buf) - 1);
}

}  // namespace

bool rfParamsPlausible(const RfParams& p) {
  // SF5..SF12 is the SX126x LoRa range. SF13..SF14 exist on the SX1261/2 as
  // long-SF mode; the Heltec V4 does not use it and pretending to support it
  // here would be a claim the radio layer cannot honour.
  if (p.spreadingFactor < 5 || p.spreadingFactor > 12) return false;

  if (p.codingRateDenominator < 5 || p.codingRateDenominator > 8) return false;

  // BW is not a discrete menu on the SX126x -- it is a fractional register
  // value -- so it is checked as a range. 7.0 kHz to 510 kHz is what the
  // part accepts in LoRa mode.
  if (!(p.bandwidthKHz >= 7.0f && p.bandwidthKHz <= 510.0f)) return false;

  if (!(p.frequencyMHz > 150.0f && p.frequencyMHz < 960.0f)) return false;

  return true;
}

bool sameRfPlan(const RfParams& a, const RfParams& b, float toleranceKHz) {
  if (std::fabs(a.frequencyMHz - b.frequencyMHz) * 1000.0f > toleranceKHz) return false;
  if (a.bandwidthKHz != b.bandwidthKHz) return false;
  if (a.spreadingFactor != b.spreadingFactor) return false;
  if (a.codingRateDenominator != b.codingRateDenominator) return false;
  return true;
}

std::string planKey(const RfParams& p) {
  return format("%.3f/%.0f/SF%u/4-%u", static_cast<double>(p.frequencyMHz),
                static_cast<double>(p.bandwidthKHz),
                static_cast<unsigned>(p.spreadingFactor),
                static_cast<unsigned>(p.codingRateDenominator));
}

std::string describeRf(const RfParams& p) {
  return format("%.3fMHz %.0fkHz SF%u 4/%u %s %s", static_cast<double>(p.frequencyMHz),
                static_cast<double>(p.bandwidthKHz),
                static_cast<unsigned>(p.spreadingFactor),
                static_cast<unsigned>(p.codingRateDenominator),
                p.explicitHeader ? "explicit" : "implicit",
                p.crcOn ? "crc" : "nocrc");
}

const char* checkName(Check c) {
  switch (c) {
    case Check::Passed:
      return "ok";
    case Check::Failed:
      return "bad";
    case Check::Untested:
    default:
      return "untested";
  }
}

bool likelyNoise(const LinkEvidence& e) {
  // Below the noise floor is noise. Also: a frame the radio refused on sync or
  // header never became a payload at all, so whatever bytes we are looking at
  // did not come from this frame and must not be attributed to it.
  if (e.rssiDbm < kNoiseFloorDbm) return true;
  if (e.syncWordCheck == Check::Failed) return true;
  if (e.headerCheck == Check::Failed) return true;
  return false;
}

Check strongestCheck(const LinkEvidence& e) {
  // "Strongest" means "the most trustworthy positive statement available".
  // A pass on the payload CRC implies the header survived too, so Passed on the
  // CRC outranks everything. A failure anywhere outranks any pass elsewhere,
  // because a frame that failed one check was not a good frame no matter what
  // else it scored.
  if (e.crcCheck == Check::Failed) return Check::Failed;
  if (e.crcCheck == Check::Passed) return Check::Passed;
  if (e.headerCheck == Check::Failed) return Check::Failed;
  if (e.headerCheck == Check::Passed) return Check::Passed;
  if (e.syncWordCheck == Check::Failed) return Check::Failed;
  if (e.syncWordCheck == Check::Passed) return Check::Passed;
  return Check::Untested;
}

std::string describeEvidence(const LinkEvidence& e) {
  std::string s;
  if (e.syncWordAvailable) {
    s += format("sync 0x%02X(%s) ", static_cast<unsigned>(e.syncWord),
                checkName(e.syncWordCheck));
  } else {
    s += "sync n/a ";
  }
  s += format("hdr %s crc %s rssi %d snr %.1f", checkName(e.headerCheck),
              checkName(e.crcCheck), static_cast<int>(e.rssiDbm),
              static_cast<double>(e.snrDb));
  return s;
}

}  // namespace sniff
