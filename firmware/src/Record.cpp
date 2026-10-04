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
  // Clamped, not trusted. `digits` reaches here from decoders, and a format buffer
  // sized for the two common cases is a buffer someone eventually overflows: a caller
  // asking for 100 digits produced "0x%0100" truncated to "0x%01" in an 8-byte buffer,
  // which formats as literal garbage rather than as a number. Eight is every digit a
  // uint32_t can have.
  if (digits < 1) digits = 1;
  if (digits > 8) digits = 8;

  char fmt[16];
  const int fn = std::snprintf(fmt, sizeof(fmt), "0x%%0%dX", digits);
  if (fn < 0 || static_cast<std::size_t>(fn) >= sizeof(fmt)) return false;

  char buf[kValueBytes];
  const int n = std::snprintf(buf, sizeof(buf), fmt, static_cast<unsigned>(value));
  if (n < 0) return false;
  return add(key, buf);
}

bool DecodedFields::addFloat(const char* key, double value, int decimals) {
  // Clamped for the same reason. Six is past the point where a JSON field gains
  // information: a double carries about 15 significant digits, and a field wider than
  // that is noise in a capture file.
  if (decimals < 0) decimals = 0;
  if (decimals > 6) decimals = 6;

  char fmt[16];
  const int fn = std::snprintf(fmt, sizeof(fmt), "%%.%df", decimals);
  if (fn < 0 || static_cast<std::size_t>(fn) >= sizeof(fmt)) return false;

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
    // The room is computed once, before the call, and the loop stops when it runs out.
    //
    // Passing `sizeof(buf) - len` inline and hoping GCC can prove it is at least one
    // byte is how this ended up flagged on the Linux runner: it could not, and "region
    // of size 0" for a `%s` is a truncation waiting to happen. Stating the bound here
    // is both the fix and the proof.
    if (len + 1 >= sizeof(buf)) break;
    const std::size_t room = sizeof(buf) - len;
    const int w = std::snprintf(buf + len, room, " %s=%s", r.decoded.fields[i].key,
                                r.decoded.fields[i].value);
    if (w <= 0) break;
    // A short write means the field did not fit. Stop rather than advance past the end:
    // `len` is only advanced by a count that provably fits.
    if (static_cast<std::size_t>(w) >= room) break;
    len += static_cast<std::size_t>(w);
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
