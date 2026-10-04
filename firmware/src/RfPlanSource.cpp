// SPDX-License-Identifier: MIT

#include "sniffer/RfPlanSource.hpp"

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace sniff {
namespace {

// Append a note, comma separated, bounded. Notes accumulate across the resolution
// steps rather than each step overwriting the last, because an operator reading
// one line needs all of them: "frequency imported from the slot's own settings,
// this plan is not the community default" is one fact plus one consequence.
void note(PlanResolution* r, const char* text) {
  std::size_t used = std::strlen(r->notes);
  if (used + 2 >= sizeof(r->notes)) return;

  if (used > 0) {
    r->notes[used] = ',';
    r->notes[used + 1] = ' ';
    r->notes[used + 2] = '\0';
  }
  const std::size_t at = std::strlen(r->notes);
  std::size_t i = 0;
  for (; at + i + 1 < sizeof(r->notes) && text[i] != '\0'; ++i) r->notes[at + i] = text[i];
  r->notes[at + i] = '\0';
}

char lowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool nameIs(const char* name, const char* want) {
  std::size_t i = 0;
  for (; name[i] != '\0' && want[i] != '\0'; ++i) {
    if (lowerAscii(name[i]) != lowerAscii(want[i])) return false;
  }
  return name[i] == '\0' && want[i] == '\0';
}

// Cut a comment out of a line in place: `//...`, and a trailing `/* ... */`.
// Block comments spanning lines are not handled, because a settings header does not
// contain them -- it is generated code -- and a half-handled one would be worse
// than none.
void stripComment(char* line) {
  char* slashes = std::strstr(line, "//");
  if (slashes != nullptr) *slashes = '\0';

  char* open = std::strstr(line, "/*");
  if (open == nullptr) return;
  char* close = std::strstr(open + 2, "*/");
  if (close != nullptr) {
    *open = '\0';
    return;
  }
  // An unterminated block comment: drop the rest of the line rather than reading
  // the tail as a define.
  *open = '\0';
}

void trimTrailing(char* s) {
  std::size_t n = std::strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) {
    s[--n] = '\0';
  }
}

// MeshCore persists its radio settings under these names. Listed explicitly
// rather than matched by prefix, because the prefix form (`RADIO_*`) would also
// swallow `RADIO_SPI_*` and turn a pin assignment into a bandwidth.
bool isRadioKey(const char* name, const char** which) {
  static const char* const kNames[] = {"RADIO_FREQ",
                                       "RADIO_BW",
                                       "RADIO_SF",
                                       "RADIO_CR",
                                       "LORA_SYNC_WORD"};
  for (std::size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); ++i) {
    if (nameIs(name, kNames[i])) {
      *which = kNames[i];
      return true;
    }
  }
  // Meshtastic's own config keys, for the case where the slot held a Meshtastic
  // image. Same explicit list for the same reason.
  if (nameIs(name, "lora.frequency")) {
    *which = "lora.frequency";
    return true;
  }
  if (nameIs(name, "lora.bandwidth")) {
    *which = "lora.bandwidth";
    return true;
  }
  if (nameIs(name, "lora.spreading_factor")) {
    *which = "lora.spreading_factor";
    return true;
  }
  if (nameIs(name, "lora.coding_rate")) {
    *which = "lora.coding_rate";
    return true;
  }
  return false;
}

}  // namespace

ImportedSettings importSettings(const char* text) {
  ImportedSettings out;
  if (text == nullptr || text[0] == '\0') return out;

  // The comparison plan: whatever the region default resolved to. A settings file
  // that agrees with it is unremarkable; one that does not is worth saying out
  // loud, because the operator will otherwise conclude the band is dead.
  RfParams community;
  community.frequencyMHz = 869.525f;

  // A working copy: the parser rewrites lines in place, and the caller's buffer
  // may be a read-only string literal in flash.
  constexpr std::size_t kMaxText = 2048;
  char work[kMaxText];
  std::size_t n = std::strlen(text);
  if (n >= sizeof(work)) n = sizeof(work) - 1;
  std::memcpy(work, text, n);
  work[n] = '\0';

  char* cursor = work;
  while (cursor != nullptr && *cursor != '\0') {
    char* line = cursor;
    char* nl = std::strchr(cursor, '\n');
    if (nl != nullptr) {
      *nl = '\0';
      cursor = nl + 1;
    } else {
      cursor = nullptr;
    }

    stripComment(line);
    trimTrailing(line);

    // Skip leading whitespace.
    char* p = line;
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '\0') continue;

    if (std::strncmp(p, "#define", 7) != 0) continue;
    p += 7;
    while (*p == ' ' || *p == '\t') ++p;

    // Key is up to whitespace or '='.
    char* key = p;
    while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '=') ++p;
    const char* keyEnd = p;
    while (*p == ' ' || *p == '\t') ++p;

    // Optional '=', then the value.
    if (*p == '=') {
      ++p;
      while (*p == ' ' || *p == '\t') ++p;
    }

    *const_cast<char*>(keyEnd) = '\0';
    const char* value = p;
    if (*value == '\0') continue;

    const char* which = nullptr;
    if (!isRadioKey(key, &which)) continue;
    ++out.recognisedKeys;

    if (nameIs(which, "RADIO_FREQ") || nameIs(which, "lora.frequency")) {
      const float f = std::strtof(value, nullptr);
      if (f > 0.0f) {
        out.frequencyMHz = f;
        out.hasFrequency = true;
      }
    } else if (nameIs(which, "RADIO_BW") || nameIs(which, "lora.bandwidth")) {
      const float b = std::strtof(value, nullptr);
      if (b > 0.0f) {
        out.bandwidthKHz = b;
        out.hasBandwidth = true;
      }
    } else if (nameIs(which, "RADIO_SF") || nameIs(which, "lora.spreading_factor")) {
      const long sf = std::strtol(value, nullptr, 10);
      if (sf >= 5 && sf <= 12) {
        out.spreadingFactor = static_cast<std::uint8_t>(sf);
        out.hasSpreadingFactor = true;
      }
    } else if (nameIs(which, "RADIO_CR") || nameIs(which, "lora.coding_rate")) {
      const long cr = std::strtol(value, nullptr, 10);
      if (cr >= 5 && cr <= 8) {
        out.codingRateDenominator = static_cast<std::uint8_t>(cr);
        out.hasCodingRate = true;
      }
    } else if (nameIs(which, "LORA_SYNC_WORD")) {
      const long sw = std::strtol(value, nullptr, 16);
      if (sw >= 0 && sw <= 255) {
        out.syncWord = static_cast<std::uint8_t>(sw);
        out.hasSyncWord = true;
      }
    }
  }

  if (out.hasFrequency && out.frequencyMHz != community.frequencyMHz) {
    out.samePlanAsCommunityDefault = false;
  }
  return out;
}

const char* planOriginName(PlanOrigin o) {
  switch (o) {
    case PlanOrigin::Override:
      return "command line";
    case PlanOrigin::BuildFlags:
      return "build flags";
    case PlanOrigin::ImportedSettings:
      return "imported settings";
    case PlanOrigin::RegionDefault:
      return "region default";
    case PlanOrigin::Unset:
    default:
      return "unset";
  }
}

PlanResolution resolvePlan(const PlanInputs& in) {
  PlanResolution out;
  out.plan = in.regionPlan;
  out.origin = PlanOrigin::RegionDefault;
  out.notes[0] = '\0';

  // 1. An explicit override wins over everything, including an implausible value.
  //    The operator who typed a frequency meant it, and a plausibility check that
  //    silently ignores it at boot is how you get "the firmware ignored my
  //    setting".
  if (in.overrideFrequencyMHz > 0.0f) {
    out.plan.frequencyMHz = in.overrideFrequencyMHz;
    out.origin = PlanOrigin::Override;
    note(&out, "frequency overridden");
  } else if (in.buildPlanValid) {
    // 2. Build flags, when the build named a plan.
    out.plan = in.buildPlan;
    out.origin = PlanOrigin::BuildFlags;
  } else if (in.settingsText != nullptr && in.settingsText[0] != '\0') {
    // 3. The settings already in this slot's filesystem. This is what makes "boot
    //    the sniffer instead of the repeater" land on the repeater's channel
    //    rather than on a default that might be 3.65 MHz away.
    const ImportedSettings imported = importSettings(in.settingsText);
    if (imported.anything()) {
      out.origin = PlanOrigin::ImportedSettings;
      if (imported.hasFrequency) {
        out.plan.frequencyMHz = imported.frequencyMHz;
        note(&out, "frequency imported from this slot's settings");
      }
      if (imported.hasBandwidth) {
        out.plan.bandwidthKHz = imported.bandwidthKHz;
        note(&out, "bandwidth imported");
      }
      if (imported.hasSpreadingFactor) {
        out.plan.spreadingFactor = imported.spreadingFactor;
        note(&out, "spreading factor imported");
      }
      if (imported.hasCodingRate) {
        out.plan.codingRateDenominator = imported.codingRateDenominator;
        note(&out, "coding rate imported");
      }
      if (!imported.samePlanAsCommunityDefault) {
        // Not a warning. A sniffer exists precisely to look at plans that are not
        // the default. But it is stated, so an operator who hears nothing knows to
        // check this line before deciding the band is dead.
        note(&out, "this plan is not the community default, so nothing on the default plan "
                   "will be heard");
      }
    }
  }

  // 4. Region default, already assigned.

  // The sync word is deliberately not part of a chosen plan. Promiscuous capture
  // requires the radio to accept any preamble, and a hard-coded sync word here would
  // be the single most likely way to build a sniffer that quietly hears one protocol
  // only -- so the decision is stated, using the word an operator would search for.
  note(&out, "promiscuous capture: sync matching relaxed so the preamble byte is read per "
             "frame");

  if (!rfParamsPlausible(out.plan)) {
    note(&out, "WARNING: outside what the SX1262 accepts, see docs/RF-PLAN.md");
  }
  return out;
}

std::string describeResolution(const PlanResolution& r) {
  std::string s = describeRf(r.plan);
  s += " (from ";
  s += planOriginName(r.origin);
  s += ")";
  if (r.notes[0] != '\0') {
    s += " ";
    s += r.notes;
  }
  return s;
}

}  // namespace sniff
