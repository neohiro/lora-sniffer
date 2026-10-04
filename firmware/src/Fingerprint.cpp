// SPDX-License-Identifier: MIT

#include "sniffer/Fingerprint.hpp"

#include <cstdio>

namespace sniff {

std::uint64_t fingerprintBytes(const std::uint8_t* data, std::size_t length) {
  std::uint64_t h = kFnvOffsetBasis;
  if (data == nullptr) return h;
  for (std::size_t i = 0; i < length; ++i) {
    h = fnv1aStep(h, data[i]);
  }
  return h;
}

std::uint64_t fingerprintFrame(const std::uint8_t* data, std::size_t length,
                               std::uint8_t syncWord, bool syncWordAvailable) {
  // The sync byte is hashed first, so that a wildcard (no byte available) and a
  // real 0x00 produce different fingerprints. Merging those two would be a
  // silent, invisible bug in exactly the case this module exists to handle.
  std::uint64_t h = kFnvOffsetBasis;
  h = fnv1aStep(h, syncWordAvailable ? syncWord : 0xFFu);
  return fingerprintBytes(data, length) ^ (h * kFnvPrime);
}

std::string toHex64(std::uint64_t value) {
  char buf[17];
  const int n = std::snprintf(buf, sizeof(buf), "%016llx",
                              static_cast<unsigned long long>(value));
  if (n <= 0) return std::string(16, '0');
  return std::string(buf, 16);
}

}  // namespace sniff
