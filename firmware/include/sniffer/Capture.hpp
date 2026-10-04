// SPDX-License-Identifier: MIT
//
// CaptureEngine -- one call, one fully populated Record.
//
// Everything before this file was a separate question: what modulation is this,
// which protocol, which decoder, is it worth repeating, does the operator want
// it. This is where the answers are combined, in a fixed order, so that there is
// exactly one code path through the firmware and one thing to test.
//
// The order matters and is not arbitrary:
//
//   1. **Corrupt and noise are decided first**, before any parsing. A frame the
//      radio refused at the preamble never became a payload, so parsing it would
//      attribute structure to bytes that were never received. This is the one
//      place where a decode could have been confidently wrong, and it is closed by
//      checking it before anything else runs.
//
//   2. **The classifier runs next**, on the raw bytes plus whatever link evidence
//      the radio gave. It is pure and cheap and it does not need the payload
//      decoded, so it can be wrong in an obvious, reportable way rather than a
//      subtle one.
//
//   3. **The protocol decoder runs third**, but only if the frame survived step 1
//      and only if the classifier named a protocol this firmware can actually
//      decode. That last condition is what keeps an unattributable frame
//      unattributable instead of being force-fed to whatever decoder happens to be
//      first in a switch.
//
//   4. **The fingerprint is taken last**, over the raw bytes and the sync word. Not
//      over the decoded fields, because two frames that decoded to the same text
//      are not the same frame -- they may be two devices quoting each other -- and
//      merging them would hide the very repetition the operator is hunting for.
//
// `CaptureEngine` owns the repeat table, the counters and the filter, so the
// firmware's main loop is a poll and a call, and the tests can drive an entire
// capture session without touching a radio.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Classifier.hpp"
#include "sniffer/Counters.hpp"
#include "sniffer/Filter.hpp"
#include "sniffer/Fingerprint.hpp"
#include "sniffer/Record.hpp"

namespace sniff {

struct CaptureOptions {
  // Whether decoded message text may be shown. Defaults to true because that is
  // the entire point of the tool; set false on a shared display and the decoders
  // emit a redaction marker instead of the text, so the setting cannot be
  // bypassed by a different code path.
  bool plainText = true;

  // Whether the raw bytes are included in the emitted record. Off would be
  // tidier and useless: a capture you cannot re-decode with a future firmware is
  // not a capture.
  bool includeBytes = true;

// Cap on the raw bytes carried per record, for the `data` field of the JSONL.
  //
  // The default is the whole frame: a capture tool exists to be the record of what was
  // on the air, and quietly dropping the tail of a 255-byte frame loses exactly the part
  // an unknown-protocol investigation needs. It costs no memory to keep it -- `Record`
  // reserves `kMaxFrameBytes` either way -- it only makes a line longer, so the lever for
  // "keep this readable at 115200 baud" is the ring size, not this field.
  //
  // Lower it deliberately, with `maxBytes = N`, when streaming to a slow console.
  std::uint8_t maxBytes = kMaxFrameBytes;
};

class CaptureEngine {
 public:
  CaptureEngine() { counters_.windowStartMs = 0; }

  void setOptions(const CaptureOptions& o) { options_ = o; }
  const CaptureOptions& options() const { return options_; }

  // Replace the filter. Returns false and leaves the previous filter in place on a
  // bad specification -- a sniffer that ended up filtering nothing because of a
  // typo would look exactly like a silent band.
  bool setFilter(const char* spec);
  bool setFilter(const FilterSpec& f) {
    filter_ = f;
    return true;
  }
  FilterSpec& filter() { return filter_; }
  const FilterSpec& filter() const { return filter_; }

  Counters& counters() { return counters_; }
  const Counters& counters() const { return counters_; }

  FingerprintTable& repeats() { return repeats_; }

  void reset();

  // Process one received frame. `link` carries whatever the radio was willing to
  // report; nothing is inferred here that the radio did not state.
  //
  // The returned record is owned by the engine and is overwritten by the next
  // call. That is intentional -- it keeps a 1928-byte record out of the caller's
  // stack and makes the common case (poll, print, continue) allocation-free.
  const Record& capture(const std::uint8_t* data, std::size_t length, const LinkEvidence& link,
                        const RfParams& listenPlan, std::uint32_t timestampMs);

  // Roll the rate window. Called from the main loop rather than from capture(),
  // because it is about time passing, not about frames arriving.
  void tick(std::uint32_t nowMs) { counters_.rollWindow(nowMs); }

 private:
  CaptureOptions options_;
  FilterSpec filter_ = passAll();
  FingerprintTable repeats_;
  Counters counters_;
  Record record_;
  std::uint32_t seq_ = 0;
};

}  // namespace sniff
