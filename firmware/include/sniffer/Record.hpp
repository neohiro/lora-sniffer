// SPDX-License-Identifier: MIT
//
// Record -- one received frame, with everything known about it.
//
// The design decision in this file is `DecodedFields`: a decoder does not
// serialise itself. It publishes key/value pairs, and the JSONL writer, the
// terminal renderer and the OLED renderer all read the same list. Adding a
// decoder therefore adds rows, not three serialisers, and there is no way for
// the JSON on the wire and the text on the screen to disagree -- which is the
// failure that makes a capture stream untrustworthy a month later, when
// somebody is trying to work out what a frame actually was.
//
// The list is fixed capacity and never allocates. On a device whose job is to
// print a serial line thousands of times an hour, an unbounded string built per
// frame is a fragmentation bug waiting for the worst possible moment.
//
// `listenPlan` is repeated on every record rather than sent once as a header.
// It costs 20 bytes and it means a capture file is self-describing: a line
// lifted out of the middle of a log still says what the sniffer was listening
// for, which is the single most common thing a reader of a capture wants to
// know and the thing a header-only format loses the moment it is split, mailed,
// or grepped.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/PlanRegistry.hpp"
#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"
#include "sniffer/RfPlan.hpp"

namespace sniff {

// Longest frame the radio can deliver into one buffer, and the documented
// MeshCore payload ceiling. 255 is the SX126x buffer size; a frame longer than
// that cannot exist as a single received packet.
constexpr std::size_t kMaxFrameBytes = 255;

// A decoder's output, as ordered named fields.
struct DecodedFields {
  static constexpr std::size_t kMaxFields = 12;
  static constexpr std::size_t kKeyBytes = 24;
  static constexpr std::size_t kValueBytes = 88;

  struct Field {
    char key[kKeyBytes] = {};
    char value[kValueBytes] = {};
  };

  std::uint8_t count = 0;
  Field fields[kMaxFields] = {};

  void clear() { count = 0; }

  // Adds a field, truncating the value rather than dropping it: a half-shown value
  // is better than a silently missing one, and the JSON writer marks truncation.
  bool add(const char* key, const char* value);
  bool add(const char* key, unsigned long value);
  bool addHex(const char* key, std::uint32_t value, int digits);
  bool addFloat(const char* key, double value, int decimals);

  const Field* find(const char* key) const;
};

// Everything the sniffer knows about one frame.
struct Record {
  // Monotonic within one boot. Restarts at 0 on reboot, which is deliberate: a
  // sniffer that cannot run for months should not need a 64-bit counter to stay
  // unique, and a sequence number that wraps visibly is better than one that
  // wraps invisibly.
  std::uint32_t seq = 0;

  // Milliseconds since boot, from the same clock the LoRa airtime math uses.
  std::uint32_t timestampMs = 0;

  LinkEvidence link;

  // The modulation we were listening for. Repeated per record on purpose.
  RfParams listenPlan;

  Protocol protocol = Protocol::Unknown;
  PlanVerdict verdict;
  Provenance provenance;

  std::uint64_t fingerprint = 0;

  // How many times this exact fingerprint has been seen since boot, including
  // this sighting. Filled in by the caller via a FingerprintTable.
  std::uint32_t repeatCount = 1;

  std::uint8_t length = 0;
  std::uint8_t data[kMaxFrameBytes] = {};

  DecodedFields decoded;

  // -------------------------------------------------------------------------
  // Node identity
  // -------------------------------------------------------------------------
  //
  // Structured, and set by the protocol decoders rather than derived from the
  // rendered text. Deriving it from `decoded` would make the device list depend on
  // a formatting decision, which is the kind of coupling that produces a device
  // list that silently empties when somebody renames a JSON key.
  //
  // Four bytes of identity, which is MeshCore's own node-hash width and
  // Meshtastic's node-number width. LoRaWAN's DevEUI is eight, so the leading four
  // are used and the full value stays in `decoded` and in the capture's hex.
  static constexpr std::size_t kIdentityBytes = 4;
  static constexpr std::size_t kRecordNameBytes = 24;
  static constexpr std::size_t kRecordTextBytes = 48;

  bool hasIdentity = false;
  Protocol identityProtocol = Protocol::Unknown;
  std::uint8_t identity[kIdentityBytes] = {};

  // Graph distance when the protocol exposes one. `hopsValid` is separate because
  // an unattributable frame has no path field at all, which is not the same as
  // being adjacent to the sniffer.
  bool hopsValid = false;
  std::uint8_t hops = 0;

  std::uint8_t role = 0;

  bool hasName = false;
  char name[kRecordNameBytes] = {};

  bool hasText = false;
  char text[kRecordTextBytes] = {};

  // True when the radio reported a CRC failure, so `data` is not the bytes that
  // were sent. Everything decoded from such a frame is suspect and the JSON
  // carries this flag so a reader cannot mistake it for a good capture.
  bool corrupt = false;

  // True when the frame was below the noise floor, or was rejected at the
  // preamble. These are counted but excluded from protocol statistics.
  bool noise = false;

  // True when the record was dropped by the active filter. Kept on the record so
  // the host tool can show "N frames matched nothing in your filter" rather than
  // leaving the operator to wonder whether the filter ate them.
  bool filtered = false;
};

// Clear a record for reuse, keeping nothing.
void resetRecord(Record* r);

// One-line terminal rendering, e.g.
//   "000412 MC grp_txt chan=0x8f hops=3 text=\"hi\" x14 !4b2e rssi-103"
void describeRecord(const Record& r, char* out, std::size_t cap);

}  // namespace sniff
