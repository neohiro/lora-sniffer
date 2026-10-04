// SPDX-License-Identifier: MIT
//
// Filter -- the difference between a sniffer and a firehose.
//
// Everything this firmware hears is also everything it cannot understand. On the
// EU band with a MeshCore repeater a few hundred metres away, the frames the
// operator actually wants -- the MeshCore group text, the Meshtastic adverts, and
// above all the unidentified frames nobody can explain -- are a small minority of
// what arrives. A sniffer that prints all of it at 115200 baud is a sniffer
// nobody leaves running.
//
// So filtering is not a convenience here, it is the feature. Three requirements
// shaped it:
//
//   * **It must be settable from the serial console and from the host tool, with
//     one grammar.** An operator standing next to the board types
//     `filter untraceable=true`; the same string works as
//     `sniffctl.py --filter untraceable=true`. Two grammars would mean the filter
//     that was tested is not the filter in use.
//
//   * **Every rule defaults to "show me".** An unset filter shows everything.
//     A filter is a narrowing, and a narrowing that silently starts hiding
//     frames because a field was left unset is how an operator concludes there is
//     nothing on the air.
//
//   * **The active filter must be printable in one line.** After changing a
//     filter you must be able to see exactly what you now have. `describe()` is
//     not a debug extra; it is how the operator avoids spending an evening
//     wondering why a capture is empty.
//
// Grammar, comma-separated, `key=value` or `key<op>value`:
//
//   proto=mc,mt                protocol tag or full name, case-insensitive
//   net=meshcore,meshtastic    network community or full name
//   attrib=unattributed        attributed | partial | unattributed
//   untraceable=true           only frames no decoder could name
//   anomaly=true               only frames that failed a structural check
//   rssi<-90                   strict less-than; also rssi> and rssi=
//   repeat>=5                  sighting count of this exact fingerprint
//   fp=4b2e1f...               exact fingerprint, 16 hex digits
//   text=hello                 case-insensitive substring of any decoded value
//   noise=false                include frames below the noise floor (default off)
//   corrupt=false              include frames the radio reported a CRC failure on
//
// An empty string is a valid filter that matches everything.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Record.hpp"

namespace sniff {

struct FilterSpec {
  // Off by default, so an unset filter is a no-op rather than a surprise.
  bool enabled = false;

  // --- narrowing rules, all "unset means show me" ---

  bool anyProtocol = false;
  bool protocol[6] = {};

  bool anyNetwork = false;
  bool network[6] = {};

  bool anyAttribution = false;
  bool attribution[3] = {};

  bool onlyUntraceable = false;
  bool onlyAnomalies = false;

  // Strict by default, because "weaker than -90 dBm" is what an operator means and
  // `rssi<-90` including the boundary would quietly change the answer. `rssi=` is
  // the one form that is inclusive, which is why it is a separate flag rather than
  // a special case of the operator.
  bool hasRssi = false;
  bool rssiIsLowerBound = false;
  bool rssiIsExact = false;
  std::int16_t rssi = 0;

  bool hasRepeat = false;
  std::uint32_t repeatMin = 0;

  bool hasFingerprint = false;
  std::uint64_t fingerprint = 0;

  bool hasText = false;
  char text[32] = {};

  // --- inclusions, both default-on so an unset filter is not a filter ---

  bool includeNoise = false;
  bool includeCorrupt = true;
};

// A filter that matches everything. Returned by value; used as the initial state
// and as the fallback when a spec string cannot be parsed.
FilterSpec passAll();

// Parse a spec string. On a bad rule, returns false and writes a short reason
// into `error` rather than accepting a silently narrowed filter -- a filter that
// quietly dropped half of what the operator asked for would be indistinguishable
// from a quiet band.
bool parseFilter(const char* spec, FilterSpec* out, char* error, std::size_t errorCap);

// True when the record passes. `enabled == false` passes everything.
bool filterMatches(const FilterSpec& f, const Record& r);

// One line describing exactly what the filter is doing, for the console echo and
// the OLED. When the filter is off this says so.
std::string describeFilter(const FilterSpec& f);

// A stable machine-readable form, for echoing back a filter that came from a
// capture file. Round-trips through parseFilter().
std::string serialiseFilter(const FilterSpec& f);

}  // namespace sniff
