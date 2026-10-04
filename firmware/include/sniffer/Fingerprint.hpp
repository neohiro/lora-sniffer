// SPDX-License-Identifier: MIT
//
// Fingerprint -- "is this the same unknown frame I saw four minutes ago?"
//
// The brief asks for easy triage of messages that cannot be traced back to any
// protocol stack. The word that makes that tractable is *repeated*. One
// unattributable frame is a curiosity; forty of them, all byte-identical, on a
// cadence of exactly 30 seconds, is a device, and it is almost certainly the
// most interesting thing on the frequency. A hex dump cannot show you that. A
// stable 64-bit fingerprint can.
//
// FNV-1a is used rather than anything stronger, and the reason is worth stating
// because it is the opposite of the usual instinct: this is not a security
// boundary. It groups frames for a human, it is not asked to resist an adversary,
// and it has to run in a few microseconds on a microcontroller that is also
// printing to a serial port. What it *does* have to be is:
//
//   * deterministic -- the same bytes must produce the same value across a
//     reboot, a firmware update and a second unit, or the operator's grouping is
//     worthless;
//   * cheap, and cheap without a heap;
//   * unlikely to collide. 64 bits over the frame sizes involved is far beyond
//     the birthday bound for any capture a person will actually read.
//
// The fingerprint deliberately covers the payload and the sync byte but *not*
// the RSSI, the timestamp or the packet counter. Those change every time the
// same device retransmits, and including them would give every repeat a fresh
// identity -- which is precisely the failure this module exists to prevent.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sniff {

constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

inline std::uint64_t fnv1aStep(std::uint64_t h, std::uint8_t b) {
  h ^= static_cast<std::uint64_t>(b);
  h *= kFnvPrime;
  return h;
}

// Fingerprint one frame's bytes.
std::uint64_t fingerprintBytes(const std::uint8_t* data, std::size_t length);

// Fingerprint a frame *including* its sync byte, which is the right unit to
// group by: two frames with identical payloads on different sync words are two
// different things arriving on the same frequency, and merging them would hide
// exactly the collision an operator is looking for.
std::uint64_t fingerprintFrame(const std::uint8_t* data, std::size_t length,
                               std::uint8_t syncWord, bool syncWordAvailable);

// 16 lowercase hex characters, zero padded. Fixed width so it sorts, diffs and
// greps like a git hash.
std::string toHex64(std::uint64_t value);

// ---------------------------------------------------------------------------
// Repeat counting
// ---------------------------------------------------------------------------

// A fixed-capacity table of recently seen fingerprints and how many times each
// was seen. Fixed capacity and no allocation, deliberately: the device must not
// be made to allocate because somebody left it on a roof for a week.
//
// Replacement policy is the simplest thing that is still useful: a new
// fingerprint replaces the least-recently-seen slot once the table is full. LRU
// needs a clock and a second field; a bump counter per slot is 32 bytes total and
// buys the same behaviour for the operator, who is looking at the last few
// thousand frames rather than the last few million.
class FingerprintTable {
 public:
  static constexpr std::size_t kCapacity = 64;

  struct Entry {
    std::uint64_t hash = 0;
    std::uint32_t count = 0;
    std::uint64_t lastSeen = 0;  // a monotonically increasing sequence number
    bool used = false;
  };

  void clear() {
    for (std::size_t i = 0; i < kCapacity; ++i) entries_[i] = Entry{};
    clock_ = 0;
  }

  // Record one sighting. Returns the running count for this fingerprint, which is
  // 1 the first time it is seen.
  std::uint32_t observe(std::uint64_t hash) {
    ++clock_;

    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (entries_[i].used && entries_[i].hash == hash) {
        ++entries_[i].count;
        entries_[i].lastSeen = clock_;
        return entries_[i].count;
      }
    }

    // Not present. Prefer an unused slot, else evict the oldest.
    std::size_t victim = kCapacity;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) {
        victim = i;
        break;
      }
    }
    if (victim == kCapacity) {
      victim = 0;
      for (std::size_t i = 1; i < kCapacity; ++i) {
        if (entries_[i].lastSeen < entries_[victim].lastSeen) victim = i;
      }
    }

    entries_[victim].hash = hash;
    entries_[victim].count = 1;
    entries_[victim].lastSeen = clock_;
    entries_[victim].used = true;
    return 1;
  }

  // Current count without recording a sighting.
  std::uint32_t countOf(std::uint64_t hash) const {
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (entries_[i].used && entries_[i].hash == hash) return entries_[i].count;
    }
    return 0;
  }

  std::size_t size() const {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (entries_[i].used) ++n;
    }
    return n;
  }

  const Entry& at(std::size_t i) const { return entries_[i]; }

  // The most-repeated fingerprint currently held, and its count. This is the
  // single number behind "something out there is talking to itself on a timer",
  // and it is what the OLED shows and `sniffctl.py stats` leads with.
  bool mostRepeated(std::uint64_t* hash, std::uint32_t* count) const {
    std::size_t best = kCapacity;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) continue;
      if (best == kCapacity || entries_[i].count > entries_[best].count) best = i;
    }
    if (best == kCapacity) return false;
    if (hash != nullptr) *hash = entries_[best].hash;
    if (count != nullptr) *count = entries_[best].count;
    return true;
  }

 private:
  Entry entries_[kCapacity];
  std::uint64_t clock_ = 0;
};

}  // namespace sniff
