// SPDX-License-Identifier: MIT
//
// Jsonl -- the capture format, and the reason there is only one.
//
// Every record is one line of JSON, one object, no wrapping array, no trailing
// comma. That is the whole specification, and the reasons for it are worth
// stating because they constrain the firmware:
//
//   * **It is appendable.** A capture that is still being written is still
//     valid, and every line already on disk is valid. There is no "finish" step
//     and no footer to lose to a power cut on a roof.
//
//   * **It is greppable.** `grep unattributed capture.jsonl` works. So does
//     `grep '"proto":"meshtastic"'`, and so does a person reading it in a text
//     editor three months later with no tooling at all.
//
//   * **It is one line per frame**, so a dropped serial byte costs one frame and
//     desynchronises nothing. A length-prefixed binary format has the opposite
//     property, which is why the compact form in Wire.hpp exists for BLE and this
//     one exists for the serial port and the file.
//
// The field names are a contract with tools/sniffctl.py and are versioned by
// firmware: the first key is always the format version. A sniffer whose output
// changes shape between releases is a sniffer nobody can write a filter for.
//
// The one genuinely dangerous field is `decoded`, because `text` and `name` come
// off the air and are controlled by whoever sent the frame. Everything written
// here goes through jsonEscape(): a message containing a quote, a backslash or a
// control character must not be able to break the line, and a message containing
// `","proto":"meshcore","` must not be able to forge a field. That is not
// hypothetical -- it is the first thing anybody does when they notice their mesh
// is being logged.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Record.hpp"

namespace sniff {

// Bumped only when an existing key changes meaning or disappears. Additive
// changes do not bump it: sniffctl.py is expected to ignore what it does not
// know, which is why an older tool can read a newer capture.
constexpr std::uint16_t kCaptureFormatVersion = 1;

// The largest line this can produce, for callers sizing a buffer. A record with
// the maximum number of decoded fields at their maximum length, plus the raw
// bytes at the default cap.
constexpr std::size_t kMaxJsonLineBytes = 2048;

// Render one record as a single JSON object including the terminating newline.
// Returns the number of bytes written excluding the NUL, or 0 if the buffer was
// too small. Truncating a JSON line would produce a file that looks fine until a
// parser reaches the seam, so a short buffer is a refusal rather than a partial
// write.
std::size_t toJsonLine(const Record& r, char* out, std::size_t cap);

// Escape a string into a JSON string body, without the surrounding quotes.
// Exposed because the tests check it directly: an escaping bug is the one defect
// in this file that turns a logging tool into an injection vector.
std::size_t jsonEscape(const char* in, char* out, std::size_t cap);

}  // namespace sniff
