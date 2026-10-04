// SPDX-License-Identifier: MIT
//
// SlotPlan -- the sniffer as a slot tool, in the same layout the bridge uses.
//
// neohiro/meshcore-meshtastic-heltec-v4 already established the geometry this
// relies on, and nothing here changes it:
//
//   * One fixed stride per slot, app-then-filesystem, slot *n* at an address that
//     is arithmetic in *n* and independent of how many slots exist.
//   * Bootloader, partition table, otadata, NVS and coredump live below the first
//     slot and never move.
//   * Therefore growing the table is provably append-only, a rewrite can never
//     orphan live firmware, and slot *n* is at the same address whether the table
//     has one row or five.
//
// What this file adds is the sniffer's role in that layout, and one decision that
// has to be made explicitly rather than inherited:
//
//   **The sniffer gets its own slot, and its own filesystem.** Not a shared
//   filesystem with MeshCore, and not "the MeshCore slot with a flag". A sniffer
//   that booted into somebody's repeater slot would need to write its own settings
//   somewhere, and the only places available are the other side's settings -- which
//   is how a repeater's channel keys get reformatted by a tool the operator ran
//   for five minutes. `validate()` refuses any table where the sniffer's slot and
//   any other framework's slot share a filesystem label, and the refusal names the
//   pair.
//
// The slot ordering is `MeshCore, Meshtastic, Sniffer, Reticulum, LoRaWAN`. The
// sniffer is third and not first, deliberately: the first slot is what a virgin
// board offers, and the firmware that should be first into a new board is the one
// that *runs the mesh*. A board that has been sitting in a box should come up as a
// working MeshCore node, not as a logger somebody forgot to turn off. The sniffer
// is offered when it is wanted, which is after the mesh is already running.
//
// Nothing is invented about coexistence: at most one slot executes, so the sniffer
// and the repeater never run at the same time on one board. "Alongside" here means
// the sniffer can *stand in* for the repeater, listen on the repeater's channel,
// and hand the slot back without the repeater losing its settings. See
// docs/SLOTS.md.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sniff {

// The frameworks this layout holds, in the order they are offered. Reserved
// rather than implemented: Reticulum and LoRaWAN are rows so that adding one is a
// table entry, not a repartition.
enum class Role : std::uint8_t {
  MeshCore = 0,
  Meshtastic = 1,
  Sniffer = 2,
  Reticulum = 3,
  LoRaWan = 4,
  Count = 5,
};

const char* roleName(Role r);

// Slots shipped by this repository. The sniffer's own tables use these; the bridge
// repo's tables are its own and the sniffer slot is added there by hand.
constexpr std::uint8_t kSlotCount = 5;

// The stride, the app size and the filesystem size are all 32-bit. Declaring the
// stride as an 8-bit type is a mistake that costs 3 MB of layout in the worst case
// and 0 in the best, and it is written here with the width spelled out because
// `-Wconversion` in the host gate is what caught it the first time.
constexpr std::uint32_t kSlotStrideBytes = 0x300000;
constexpr std::uint32_t kSlotAppBytes = 0x200000;
constexpr std::uint32_t kSlotFsBytes = 0x100000;

constexpr std::uint32_t kBootloaderOffset = 0x0;
constexpr std::uint32_t kBootloaderSize = 0x7000;
constexpr std::uint32_t kPartitionTableOffset = 0x8000;
constexpr std::uint32_t kPartitionTableSize = 0xC000;
constexpr std::uint32_t kOtadataOffset = 0x14000;
constexpr std::uint32_t kOtadataSize = 0x2000;
constexpr std::uint32_t kNvsOffset = 0x16000;
constexpr std::uint32_t kNvsSize = 0xA000;
constexpr std::uint32_t kCoredumpOffset = 0x20000;
constexpr std::uint32_t kCoredumpSize = 0x10000;
constexpr std::uint32_t kFirstSlotOffset = kCoredumpOffset + kCoredumpSize;  // 0x30000

constexpr std::uint32_t kDefaultFlashBytes = 16u * 1024u * 1024u;

// App offsets are 64 KB aligned or the bootloader refuses the table and says
// nothing at all, which presents as a board that is simply dead.
constexpr std::uint32_t kAppAlignment = 0x10000;

// Offset of slot `index`. Pure arithmetic: no table, no state.
constexpr std::uint32_t slotOffset(std::uint8_t index) {
  return kFirstSlotOffset + static_cast<std::uint32_t>(index) * kSlotStrideBytes;
}

constexpr std::uint32_t slotFsOffset(std::uint8_t index) {
  return slotOffset(index) + kSlotAppBytes;
}

// Partition label for a slot's filesystem. Label names are load-bearing: the
// bootloader keys mount points off them, so renaming one orphans its settings.
const char* slotFsLabel(Role r);

// Which filesystem type each framework mounts. Meshtastic mounts LittleFS and
// MeshCore mounts SPIFFS; handing either the other's type makes it format the
// wrong one on boot and lose the settings of the other side of the pair.
const char* slotFsType(Role r);

// The sniffer's index. A constant rather than a lookup so a wrong table fails at
// compile time rather than at boot on a roof.

// The slot order, in one table. Kept in the header rather than in the .cpp because
// it *is* the layout description, and tools/gen_layouts.py generates the shipped
// partition CSVs from this file. Two copies of "which slot holds what" would be two
// things to forget, and the one that gets forgotten is a partition table.
struct RoleRow {
  const char* role;     // the framework name
  const char* fsLabel;  // the partition label; the bootloader keys mount points off it
  const char* fsType;   // SPIFFS or LittleFS
};

inline constexpr RoleRow kRows[] = {
    {"meshcore", "fs_meshcore", "spiffs"},
    {"meshtastic", "fs_meshtastic", "littlefs"},
    {"sniffer", "fs_sniffer", "spiffs"},
    {"reticulum", "fs_reticulum", "spiffs"},
    {"lorawan", "fs_lorawan", "spiffs"},
};

inline constexpr std::size_t kRowCount = sizeof(kRows) / sizeof(kRows[0]);

static_assert(kRowCount == static_cast<std::size_t>(Role::Count),
              "kRows and Role disagree; adding a role needs a row here");

// ---------------------------------------------------------------------------
// Layouts
// ---------------------------------------------------------------------------

// Which layout a table describes.
//
// This is not decoration. In the shared layout slot *n* holds the *n*-th framework, so
// slot 2 is the sniffer and `fs_sniffer` belongs to it. In the standalone layout slot 0
// holds the sniffer, so the same geometry pairs slot 0 with `fs_sniffer` instead.
//
// Generating the standalone table from the canonical order put `fs_meshcore` beside the
// sniffer's app partition -- which would let a MeshCore image flashed into that slot
// adopt the sniffer's settings, and which `validateForSniffer()` correctly rejects as a
// shared filesystem. The relationship between a slot and its framework is therefore
// explicit here rather than implied by an index.
enum class Layout : std::uint8_t {
  // MeshCore, Meshtastic, Sniffer, then two reserved. The table the
  // meshcore-meshtastic-heltec-v4 project also uses.
  Shared = 0,
  // The sniffer alone in slot 0, for a board with nothing else on it.
  Standalone = 1,
};

const char* layoutName(Layout l);

constexpr std::uint8_t sharedSlots() { return 5; }
constexpr std::uint8_t standaloneSlots() { return 1; }

// The framework occupying slot `index` in this layout.
constexpr Role roleAt(Layout layout, std::uint8_t index) {
  return layout == Layout::Standalone ? Role::Sniffer : static_cast<Role>(index);
}

// The sniffer's index in this layout. The shared layout's is the one worth naming,
// because a wrong table there fails at compile time rather than on a roof.
constexpr std::uint8_t kSnifferSlot = 2;

constexpr std::uint8_t snifferSlotIn(Layout layout) {
  return layout == Layout::Standalone ? 0 : kSnifferSlot;
}

constexpr std::uint8_t slotsIn(Layout layout) {
  return layout == Layout::Standalone ? standaloneSlots() : sharedSlots();
}

// How many slots this much flash can hold, derived rather than declared.
std::uint8_t maxSlotsForFlash(std::uint32_t flashSizeBytes = kDefaultFlashBytes);

// Render a layout as ESP-IDF partition CSV.
//
// Slot n's *address* depends only on n, so the CSV for three slots contains the CSV for
// two slots verbatim plus one more. That is what makes the table safe to rewrite in
// place, and it is checked by the gate rather than asserted in a comment.
//
// The *filesystem label* depends on the layout as well as the index, because which
// framework lives in slot 0 differs between the two. See `Layout`.
std::string renderSlots(Layout layout, std::uint8_t slots,
                        std::uint32_t flashSizeBytes = kDefaultFlashBytes);

// Which frameworks a layout holds, in slot order.
std::uint8_t rolesUpTo(Layout layout, std::uint8_t slots, Role* out, std::size_t max);

enum class LayoutStatus : std::uint8_t {
  Ok = 0,
  OverrunsFlash,
  MisalignedApp,
  SnifferSlotMissing,
  SharedFilesystem,
  SnifferTooSmall,
  WrongFilesystemForSlot,  // the sniffer's slot is paired with another framework's
};

const char* layoutStatusName(LayoutStatus s);

struct LayoutReport {
  LayoutStatus status = LayoutStatus::Ok;
  std::uint8_t slots = 0;
  std::uint32_t freeBytes = 0;

  // The human sentence, sized for a terminal and written to be the first thing
  // that gets read when something is wrong.
  char detail[160] = {};

  bool ok() const { return status == LayoutStatus::Ok; }
};

// Check a layout for the sniffer's specific requirements.
//
// This is deliberately not a general partition validator -- the bridge has one,
// and duplicating it here would mean two implementations drifting apart. What it
// checks is what is specific to *being the sniffer*: that the sniffer's slot exists,
// that its app fits, that its filesystem is its own, and that the whole thing fits the
// flash the chip actually reports.
//
// `validateForSniffer()` is the entry point for a shipped layout. `validateSlots()`
// takes the layout, the slot count and the sniffer's index explicitly, so the
// *impossible* layouts -- two slots of the shared layout, a shared layout with the
// sniffer in slot 0 -- are reachable from a test rather than being unreachable by
// construction. That distinction is the point: a validator that takes a Layout alone
// can only ever see the cases that were supposed to work.
LayoutReport validateSlots(Layout layout, std::uint8_t slots, std::uint8_t snifferSlot,
                           std::uint32_t flashSizeBytes = kDefaultFlashBytes);

LayoutReport validateForSniffer(Layout layout,
                                std::uint32_t flashSizeBytes = kDefaultFlashBytes);

}  // namespace sniff
