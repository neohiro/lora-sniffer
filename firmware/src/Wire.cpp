// SPDX-License-Identifier: MIT

#include "sniffer/Wire.hpp"

#include <cstdio>
#include <cstring>

namespace sniff {
namespace {

void putU16(std::uint8_t* p, std::uint16_t v) {
  p[0] = static_cast<std::uint8_t>(v & 0xFFu);
  p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFFu);
}

void putU32(std::uint8_t* p, std::uint32_t v) {
  for (std::size_t i = 0; i < 4; ++i) {
    p[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
  }
}

void putU64(std::uint8_t* p, std::uint64_t v) {
  for (std::size_t i = 0; i < 8; ++i) {
    p[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xFFu);
  }
}

std::uint16_t bytesOf(const char* s) {
  const std::size_t n = std::strlen(s);
  return static_cast<std::uint16_t>(n > 0xFFFFu ? 0xFFFFu : n);
}

}  // namespace

std::size_t toWire(const Record& r, std::uint8_t* out, std::size_t cap) {
  if (out == nullptr || cap < kWireHeaderBytes) return 0;

  std::uint8_t flags = 0;
  if (r.corrupt) flags |= kWireFlagCorrupt;
  if (r.noise) flags |= kWireFlagNoise;
  if (r.filtered) flags |= kWireFlagFiltered;
  if (r.link.syncWordAvailable) flags |= kWireFlagSyncAvailable;
  if (r.verdict.carrierOnly) flags |= kWireFlagCarrierOnly;

  // SNR as tenths of a decibel. Clamped rather than wrapped, because a wrapped
  // value would read as a perfectly ordinary-looking SNR that is simply wrong.
  float snrTenthsF = r.link.snrDb * 10.0f;
  if (snrTenthsF > 32767.0f) snrTenthsF = 32767.0f;
  if (snrTenthsF < -32768.0f) snrTenthsF = -32768.0f;
  const std::int16_t snrTenths = static_cast<std::int16_t>(snrTenthsF);

  // Decoded fields follow the payload as NUL-terminated key/value pairs with a
  // final empty key as the terminator. Two terminators is the price of not
  // needing a length prefix per field, and it keeps the layout trivially
  // walkable in a phone-side parser.
  std::size_t stringsBytes = 0;
  for (std::size_t i = 0; i < r.decoded.count; ++i) {
    stringsBytes += bytesOf(r.decoded.fields[i].key) + 1u;
    stringsBytes += bytesOf(r.decoded.fields[i].value) + 1u;
  }
  stringsBytes += 1u;  // final empty key

  const std::size_t total = kWireHeaderBytes + r.length + stringsBytes;
  if (total > cap) return 0;

  std::uint8_t* p = out;
  p[0] = kWireMagic0;
  p[1] = kWireMagic1;
  p[2] = kWireMagic2;
  p[3] = kWireMagic3;
  p[4] = kWireVersion;
  p[5] = static_cast<std::uint8_t>(kWireHeaderBytes);
  putU16(p + 6, static_cast<std::uint16_t>(total - 8u));
  p[8] = flags;
  p[9] = static_cast<std::uint8_t>(r.protocol);
  p[10] = static_cast<std::uint8_t>(r.provenance.attribution);
  p[11] = static_cast<std::uint8_t>(r.provenance.reason);
  p[12] = static_cast<std::uint8_t>(r.verdict.network);
  p[13] = static_cast<std::uint8_t>(r.verdict.confidence);
  p[14] = static_cast<std::uint8_t>(r.provenance.decoder);
  putU16(p + 15, static_cast<std::uint16_t>(r.seq & 0xFFFFu));
  putU32(p + 17, r.timestampMs);
  putU16(p + 21, static_cast<std::uint16_t>(r.link.rssiDbm));
  putU16(p + 23, static_cast<std::uint16_t>(static_cast<std::uint16_t>(snrTenths)));
  putU16(p + 25, static_cast<std::uint16_t>(r.length));
  putU64(p + 27, r.fingerprint);

  std::size_t off = kWireHeaderBytes;
  if (r.length > 0) {
    std::memcpy(p + off, r.data, r.length);
    off += r.length;
  }

  for (std::size_t i = 0; i < r.decoded.count; ++i) {
    const std::size_t kl = bytesOf(r.decoded.fields[i].key);
    std::memcpy(p + off, r.decoded.fields[i].key, kl + 1u);
    off += kl + 1u;
    const std::size_t vl = bytesOf(r.decoded.fields[i].value);
    std::memcpy(p + off, r.decoded.fields[i].value, vl + 1u);
    off += vl + 1u;
  }
  p[off] = 0x00;

  return total;
}

bool isWireFrame(const std::uint8_t* data, std::size_t length) {
  if (data == nullptr || length < kWireHeaderBytes) return false;
  if (data[0] != kWireMagic0 || data[1] != kWireMagic1 || data[2] != kWireMagic2 ||
      data[3] != kWireMagic3) {
    return false;
  }
  if (data[4] != kWireVersion) return false;
  // A header length this firmware does not know about is still a frame, and a
  // reader must be able to tell "newer, more fields" from "not a capture".
  return data[5] >= kWireHeaderBytes;
}

}  // namespace sniff
