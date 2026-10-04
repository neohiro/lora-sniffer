// SPDX-License-Identifier: MIT

#include "sniffer/MemoryBudget.hpp"

#include <cstdarg>
#include <cstdio>

#include "sniffer/Capture.hpp"
#include "sniffer/Counters.hpp"
#include "sniffer/DeviceTable.hpp"
#include "sniffer/Jsonl.hpp"
#include "sniffer/Record.hpp"
#include "sniffer/SlotPlan.hpp"
#include "sniffer/Transport.hpp"
#include "sniffer/Wire.hpp"

namespace sniff {
namespace {

void setDetail(MemoryReport* r, const char* fmt, unsigned a, unsigned b) {
  const int n = std::snprintf(r->detail, sizeof(r->detail), fmt, a, b);
  if (n < 0) r->detail[0] = '\0';
}

void setDetailKb(MemoryReport* r, const char* fmt, std::size_t a, std::size_t b) {
  const int n = std::snprintf(r->detail, sizeof(r->detail), fmt, static_cast<unsigned>(a / 1024),
                              static_cast<unsigned>(b / 1024));
  if (n < 0) r->detail[0] = '\0';
}


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

const char* fitStatusName(FitStatus s) {
  switch (s) {
    case FitStatus::Ok:
      return "ok";
    case FitStatus::FlashTooSmall:
      return "flash-too-small";
    case FitStatus::HeapTooSmall:
      return "heap-too-small";
    case FitStatus::PsramExpected:
      return "psram-expected";
    case FitStatus::SlotTooSmall:
      return "slot-too-small";
    default:
      return "unknown";
  }
}

// Every term below is a real sizeof. Adding a table to the firmware changes this
// number at compile time; there is no constant anywhere that can go stale.
std::size_t workingSetBytes(std::uint16_t deviceCapacity, std::uint16_t ringCapacity) {
  std::size_t bytes = 0;
  bytes += sizeof(CaptureEngine);
  bytes += sizeof(Record);
  bytes += sizeof(Counters);
  bytes += sizeof(FilterSpec);
  bytes += sizeof(LinkEvidence);
  bytes += sizeof(RfParams);
  bytes += sizeof(PlanVerdict);

  // The device table is capacity-parameterised, so its size is a function of the
  // capacity rather than of a template parameter. This is the one place a formula
  // appears instead of a sizeof, and it is checked against a real instance below.
  bytes += deviceTableBytes(deviceCapacity);

  // The ring holds formatted lines, not Records. A Record is 1928 bytes; a JSON line
  // is a few hundred bytes, and holding a hundred of those on a board with no PSRAM
  // is the difference between working and thrashing.
  bytes += static_cast<std::size_t>(ringCapacity) * kRingLineBytes;

  // One JSON line buffer and one wire frame buffer, for the transports.
  bytes += kMaxJsonLineBytes;
  bytes += kMaxWireBytes;

  return bytes;
}

std::size_t heapRequired(std::uint16_t deviceCapacity, std::uint16_t ringCapacity,
                         std::size_t heapFreeBytes) {
  const std::size_t working = workingSetBytes(deviceCapacity, ringCapacity);
  const std::size_t headroom =
      (heapFreeBytes / kHeapHeadroomDenominator) * kHeapHeadroomNumerator;
  return working + headroom;
}

MemoryReport checkFit(const MemoryProfile& profile, const Measured& m, std::size_t appUsedBytes) {
  MemoryReport r;
  r.slots = m.slots;
  r.capacity = maxSlotsForFlash(m.flashBytes);
  r.deviceCapacity = profile.deviceCapacity;
  r.ringCapacity = profile.ringCapacity;
  r.heapFreeBytes = m.heapFreeBytes;
  r.psramFreeBytes = m.psramFreeBytes;
  r.slotBytes = kSlotAppBytes;
  r.slotUsedBytes = appUsedBytes;

  // 1. The flash. Compared against the slot count the layout *declares*, not the
  //    count we would like. A five-slot table on an 8 MB board is a table that
  //    overruns, and the bootloader will not say so.
  if (m.slots > r.capacity) {
    r.status = FitStatus::FlashTooSmall;
    setDetail(&r, "the partition table declares %u slots but this flash holds %u at the fixed "
                  "stride. Flash the table this board reports, not the one you meant to flash",
             m.slots, static_cast<unsigned>(r.capacity));
    return r;
  }

  // 2. The profile. A PSRAM profile on a board with no PSRAM is a silent 2x
  //    overshoot of every table in the firmware, and it presents as fragmentation
  //    hours later rather than at boot.
  if (profile.psramBytes > 0 && m.psramFreeBytes == 0) {
    r.status = FitStatus::PsramExpected;
    std::snprintf(r.detail, sizeof(r.detail),
                  "the '%s' profile expects %uKB of PSRAM and none was found. Falling back is the "
                  "operator's call, not this firmware's: the capacities below assume it",
                  profile.name, static_cast<unsigned>(profile.psramBytes / 1024));
    return r;
  }

  // 3. The app image against the slot it has to live in.
  if (appUsedBytes > kSlotAppBytes) {
    r.status = FitStatus::SlotTooSmall;
    setDetailKb(&r, "the image needs %uKB but the slot holds %uKB", appUsedBytes, kSlotAppBytes);
    return r;
  }

  // 4. The heap, measured after everything else has taken its share.
  r.workingSetBytes = workingSetBytes(profile.deviceCapacity, profile.ringCapacity);
  r.heapRequiredBytes =
      heapRequired(profile.deviceCapacity, profile.ringCapacity, m.heapFreeBytes);

  if (m.heapFreeBytes < r.workingSetBytes) {
    r.status = FitStatus::HeapTooSmall;
    std::snprintf(r.detail, sizeof(r.detail),
                  "%uKB free but the working set is %uKB on the '%s' profile. A smaller profile "
                  "will run; see docs/MEMORY.md",
                  static_cast<unsigned>(m.heapFreeBytes / 1024),
                  static_cast<unsigned>(r.workingSetBytes / 1024), profile.name);
    return r;
  }

  if (m.heapFreeBytes < r.heapRequiredBytes) {
    r.status = FitStatus::HeapTooSmall;
    setDetailKb(&r,
                "%uKB free, %uKB needed with headroom. Running anyway, but expect gaps in the "
                "capture if something else claims memory later",
                m.heapFreeBytes, r.heapRequiredBytes);
    return r;
  }

  r.status = FitStatus::Ok;
  r.detail[0] = '\0';
  return r;
}

std::string renderMemory(const MemoryReport& r) {
  std::string s;
  s += format("fit         %s\n", fitStatusName(r.status));
  s += format("profile     %u devices, %u ring lines\n", static_cast<unsigned>(r.deviceCapacity),
              static_cast<unsigned>(r.ringCapacity));
  s += format("working set %uKB of %uKB free heap\n", static_cast<unsigned>(r.workingSetBytes / 1024),
              static_cast<unsigned>(r.heapFreeBytes / 1024));
  s += format("with margin %uKB\n", static_cast<unsigned>(r.heapRequiredBytes / 1024));
  s += format("app         %uKB used of %uKB slot\n", static_cast<unsigned>(r.slotUsedBytes / 1024),
              static_cast<unsigned>(r.slotBytes / 1024));
  s += format("slots       %u declared, %u fit this flash\n", static_cast<unsigned>(r.slots),
              static_cast<unsigned>(r.capacity));
  if (r.psramFreeBytes > 0) {
    s += format("psram       %uKB free\n", static_cast<unsigned>(r.psramFreeBytes / 1024));
  }
  if (!r.ok()) {
    s += format("            %s\n", r.detail);
  }
  return s;
}

}  // namespace sniff
