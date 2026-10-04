// SPDX-License-Identifier: MIT
//
// RfPlanSource -- decide what to listen for, and say where the answer came from.
//
// This is the module that makes the sniffer usable as a *stand-in* for the mesh
// firmware it replaces. The problem it solves is specific and annoying: the
// operator has a repeater on 869.525 with a MeshCore channel configured, they
// flash the sniffer into the same slot to see what is actually on the air, and
// if the sniffer defaults to a region preset instead of reading what the repeater
// was using then it either hears nothing or hears a different network, and the
// obvious conclusion -- "the mesh is quiet" -- is wrong.
//
// So the plan is resolved from four sources, in a fixed order, and the origin is
// reported every time:
//
//   1. an explicit override on the command line
//   2. the build flags
//   3. **the settings already in this slot's filesystem**
//   4. the region default
//
// Source 3 is the one that matters and the reason the sniffer slot has its own
// filesystem. When the sniffer boots it reads the settings its slot was
// provisioned with -- the ones the MeshCore image wrote, which is why the slot
// must not be wiped on a slot change -- and listens there.
//
// Parsing is `#define`-based, which is a real property of the format rather than a
// convenience: MeshCore firmware persists its settings as a C header full of
// `#define`s and includes it, so a `#define` scanner reads exactly the same
// values the firmware itself compiles with. There is no YAML to parse on a
// microcontroller and no protobuf schema to vendor, which is a large part of why
// this is 200 lines instead of 2000.
//
// Every field is optional and independently defaulted. A settings file that names
// a frequency but not a bandwidth is normal, and treating the absence of a field
// as an error would make the import useless on a default channel.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/PlanRegistry.hpp"
#include "sniffer/RfPlan.hpp"

namespace sniff {

// What a settings import managed to read. Every flag is independent, because a
// settings file that specifies two of five things is a normal file.
struct ImportedSettings {
  bool hasFrequency = false;
  float frequencyMHz = 0.0f;

  bool hasBandwidth = false;
  float bandwidthKHz = 0.0f;

  bool hasSpreadingFactor = false;
  std::uint8_t spreadingFactor = 0;

  bool hasCodingRate = false;
  std::uint8_t codingRateDenominator = 0;

  bool hasSyncWord = false;
  std::uint8_t syncWord = 0;

  // False when the imported plan differs from the community default for the
  // region. Not an error: a sniffer exists precisely to look at plans that are not
  // the default. Reported so an operator who hears nothing knows to check.
  bool samePlanAsCommunityDefault = true;

  // Number of `#define`s that were recognised as a radio setting. Zero means the
  // text was not a settings file at all, which is worth saying rather than
  // silently falling back to a default.
  std::uint8_t recognisedKeys = 0;

  bool anything() const { return recognisedKeys > 0; }
};

// Parse `#define NAME value` lines. Comments (`//`, `/* */`, `#`) are skipped.
// A line whose name is not a radio setting is ignored, not rejected: a settings
// file carries dozens of unrelated keys and stopping at the first one it does not
// recognise would make the import useless.
ImportedSettings importSettings(const char* text);

// Where a resolved plan came from. Reported, always, so that "why is it not
// hearing anything" has a one-line answer before it becomes an afternoon.
enum class PlanOrigin : std::uint8_t {
  Unset = 0,
  RegionDefault,
  ImportedSettings,
  BuildFlags,
  Override,
};

const char* planOriginName(PlanOrigin o);

// Everything resolution can consider.
struct PlanInputs {
  RfParams regionPlan;
  RfParams buildPlan;

  // Whether the build named a plan at all.
  //
  // This flag exists because `RfParams`'s defaults are a *valid* EU_868 plan, so
  // "the build specified nothing" and "the build specified the default" are
  // indistinguishable by looking at the struct. Without the flag, every firmware
  // built without `-DFREQUENCY_MHZ` would report "build flags" as its origin and
  // would silently beat a settings import -- which is exactly backwards: an
  // operator's own repeater settings should win over nothing.
  bool buildPlanValid = false;

  // <= 0 means "no override given".
  float overrideFrequencyMHz = 0.0f;

  // The text read from this slot's settings file, or nullptr.
  const char* settingsText = nullptr;
};

// Bounded notes about the resolution, e.g. "frequency imported from the slot's own
// settings, this plan is not the community default". Rendered on one line.
constexpr std::size_t kPlanNoteBytes = 160;

struct PlanResolution {
  RfParams plan;
  PlanOrigin origin = PlanOrigin::Unset;
  char notes[kPlanNoteBytes] = {};
};

PlanResolution resolvePlan(const PlanInputs& in);

std::string describeResolution(const PlanResolution& r);

}  // namespace sniff
