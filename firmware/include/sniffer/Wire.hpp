// SPDX-License-Identifier: MIT
//
// Wire -- the compact capture form, for BLE.
//
// JSONL is what gets written to a file and read by a person three months later.
// This is what goes out over Bluetooth, and the two exist because they are
// optimised for opposite ends: JSON is greppable and verbose, this is small and
// positional.
//
// The framing rules are the ones that make a lossy link survivable:
//
//   * **A 4-byte magic and an explicit version.** A phone that connects to the
//     wrong service, or to a device running last month's firmware, finds out
//     immediately rather than decoding nonsense.
//
//   * **`headerLen` and `totalLen` are both present.** A reader that meets a
//     future firmware with extra header fields skips them using `headerLen`
//     instead of misinterpreting them. That is the difference between a sniffer
//     you can update and a sniffer you have to keep in lockstep with your phone.
//
//   * **BLE notifications are not framed by the link in a way this can rely on,
//     so every field carries its own length.** One dropped notification costs one
//     record. Nothing here is a stateful stream, because a stateful stream over
//     a lossy link is a stream that desynchronises.
//
// SNR is carried as a signed 16-bit count of tenths of a decibel rather than as a
// float. Floats over a byte-oriented link invite alignment assumptions that a
// phone's BLE stack has no reason to honour.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Record.hpp"

namespace sniff {

constexpr std::uint8_t kWireMagic0 = 'L';
constexpr std::uint8_t kWireMagic1 = 'S';
constexpr std::uint8_t kWireMagic2 = 'N';
constexpr std::uint8_t kWireMagic3 = '1';
constexpr std::uint8_t kWireVersion = 1;

// magic(4) + version(1) + headerLen(1) + totalLen(2) + flags(1) + protocol(1) +
// attribution(1) + reason(1) + network(1) + confidence(1) + basis(1) +
// syncWord(1) + seq(2) + timestampMs(4) + rssi(2) + snrDecibel(2) +
// payloadLen(2) + fingerprint(8) = 36
constexpr std::size_t kWireHeaderBytes = 36;

// Flag bits in the wire flags byte.
constexpr std::uint8_t kWireFlagCorrupt = 0x01;
constexpr std::uint8_t kWireFlagNoise = 0x02;
constexpr std::uint8_t kWireFlagFiltered = 0x04;
constexpr std::uint8_t kWireFlagSyncAvailable = 0x08;
constexpr std::uint8_t kWireFlagCarrierOnly = 0x10;

// Worst case: header, a full 255-byte payload, and every decoded field at its
// maximum length with its NULs.
constexpr std::size_t kMaxWireBytes = 2048;

// Encode one record. Returns the total bytes written, or 0 if the buffer is too
// small. As with the JSON writer, a short buffer is a refusal: half a record on a
// notification is a record a phone will misparse and a user will report as a
// crash.
std::size_t toWire(const Record& r, std::uint8_t* out, std::size_t cap);

// A quick check that a buffer starts with this firmware's framing. Used by the
// phone-side and by the tests; on device it is a self-test at boot.
bool isWireFrame(const std::uint8_t* data, std::size_t length);

}  // namespace sniff
