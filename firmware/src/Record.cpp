// SPDX-License-Identifier: MIT

#include "sniffer/Record.hpp"

#include <cstdio>
#include <cstring>

#include "sniffer/Fingerprint.hpp"

namespace sniff {
namespace {

void copyBounded(char* dst, std::size_t cap, const char* src) {
  if (cap == 0) return;
  std::size_t i = 0;
  for (; i + 1 < cap && src[i] != '\0'; ++i) dst[i] = src[i];
  dst[i] = '\0';
}

bool equals(const char* a, const char* b) {
  return a != nullptr && b != nullptr && std::strcmp(a, b) == 0;
}

}  // namespace

bool DecodedFields::add(const char* key, const char* value) {
  if (count >= kMaxFields) return false;
  Field& f = fields[count];
  copyBounded(f.key, kKeyBytes, key);
  copyBounded(f.value, kValueBytes, value);
  ++count;
  return true;
}

bool DecodedFields::add(const char* key, unsigned long value) {
  char buf[kValueBytes];
  const int n = std::snprintf(buf, sizeof(buf), "%lu", value);
  if (n < 0) return false;
  return add(key, buf);
}

bool DecodedFields::addHex(const char* key, std::uint32_t value, int digits) {
  char fmt[8];
  const int fn = std::snprintf(fmt, sizeof(fmt), "0x%%0%dX", digits);
  if (fn < 0) return false;
  char buf[kValueBytes];
  const int n = std::snprintf(buf, sizeof(buf), fmt, static_cast<unsigned>(value));
  if (n < 0) return false;
  return add(key, buf);
}

bool DecodedFields::addFloat(const char* key, double value, int decimals) {
  char fmt[8];
  const int fn = std::snprintf(fmt, sizeof(fmt), "%%.%df", decimals);
  if (fn < 0) return false;
  char buf[kValueBytes];
  const int n = std::snprintf(buf, sizeof(buf), fmt, value);
  if (n < 0) return false;
  return add(key, buf);
}

const DecodedFields::Field* DecodedFields::find(const char* key) const {
  for (std::size_t i = 0; i < count; ++i) {
    if (equals(fields[i].key, key)) return &fields[i];
  }
  return nullptr;
}

void resetRecord(Record* r) {
  if (r == nullptr) return;
  // Assignment rather than memset. Record has default member initialisers, so it is
  // not trivially default-constructible and -Wclass-memaccess is right to object;
  // and a value-initialised Record is exactly what "reset" means here anyway.
  *r = Record{};
  r->repeatCount = 1;
}

void describeRecord(const Record& r, char* out, std::size_t cap) {
  if (cap == 0) return;

  // Built with snprintf into a generous buffer and then copied down, because a
  // truncated terminal line is fine and a truncated field list is not: the
  // caller wants the identifiers first and the free text last.
  char buf[320];
  int n = std::snprintf(buf, sizeof(buf), "%06u %s %s", static_cast<unsigned>(r.seq),
                        protocolTag(r.protocol), r.verdict.name);
  if (n < 0) {
    out[0] = '\0';
    return;
  }
  std::size_t len = static_cast<std::size_t>(n);
  if (len >= sizeof(buf)) len = sizeof(buf) - 1;

  for (std::size_t i = 0; i < r.decoded.count; ++i) {
    const int w = std::snprintf(buf + len, sizeof(buf) - len, " %s=%s", r.decoded.fields[i].key,
                                r.decoded.fields[i].value);
    if (w <= 0) break;
    len += static_cast<std::size_t>(w);
    if (len >= sizeof(buf) - 1) break;
  }

  const int tail = std::snprintf(buf + len, sizeof(buf) - len, " x%u !%s rssi=%d",
                                 static_cast<unsigned>(r.repeatCount),
                                 toHex64(r.fingerprint).c_str(), static_cast<int>(r.link.rssiDbm));
  if (tail > 0) {
    len += static_cast<std::size_t>(tail);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
  }

  copyBounded(out, cap, buf);
}

}  // namespace sniff
