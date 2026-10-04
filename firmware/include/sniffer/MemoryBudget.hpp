// SPDX-License-Identifier: MIT
//
// MemoryBudget -- measure the board at startup, and refuse to run on one that is
// too small.
//
// The constraint that shapes this project is that the sniffer is one guest on a
// board that belongs to somebody else's mesh. The same Heltec V4 runs MeshCore,
// Meshtastic and this firmware out of five slots, and every one of those firmware
// images expects to have the machine to itself when it boots. So:
//
//   * **The flash size is read from the chip, never assumed.** An 8 MB V3 flashed
//     with a five-slot table fails in a way that looks like a bad download, and
//     `tools/flash.py` refuses it for the same reason. Here it is the second half
//     of the same defence: the running firmware checks its own layout against the
//     chip it woke up on.
//
//   * **The working set is computed from `sizeof`, not guessed.** Every fixed table
//     in this firmware is a `constexpr`-sized struct, so `workingSetBytes()` is a
//     compile-time number that cannot drift from the code. Adding a device table
//     entry changes the number the boot check uses; there is no constant to forget
//     to bump.
//
//   * **The heap is measured, not profiled.** `freeHeap()` at boot is the only
//     number that reflects what the WiFi stack, the BLE stack and the SPIFFS
//     mount have already taken. A datasheet figure would be a lie.
//
//   * **The requirement scales down.** `MemoryProfile` carries a floor. On a bare
//     Heltec V4 with no PSRAM the device table shrinks and the ring log shrinks;
//     on a board with 8 MB of PSRAM they grow. The check is against the profile the
//     board reports, so the same binary behaves correctly on both rather than
//     quietly fragmenting on one of them.
//
// Nothing here allocates. The whole module is a struct and a function, because a
// memory check that itself needs memory is a check that cannot report a shortfall.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace sniff {

// ---------------------------------------------------------------------------
// The boards this is written against
// ---------------------------------------------------------------------------

// A floor for one class of board, not a spec for one board. `psramBytes` is the
// decisive field: everything expensive in this firmware is either moved into PSRAM
// or shrunk.
struct MemoryProfile {
  const char* name;

  std::uint32_t flashBytes;
  std::size_t heapFloorBytes;
  std::size_t psramBytes;

  // Device-list capacity for this class. Fixed at compile time so the working set
  // stays exact; a board without PSRAM carries fewer nodes rather than carrying
  // fewer nodes *and* a heap fragmenter.
  std::uint16_t deviceCapacity;

  // Capture ring entries retained for replay. Each is a JSON line, not a Record, so
  // this is a text buffer rather than a table of 1928-byte structures.
  std::uint16_t ringCapacity;
};

constexpr MemoryProfile kProfileBare = {"bare", 4u * 1024u * 1024u, 96u * 1024u, 0u, 32, 16};
constexpr MemoryProfile kProfileStandard = {"standard", 8u * 1024u * 1024u, 160u * 1024u, 0u, 64, 48};
constexpr MemoryProfile kProfilePsram = {"psram", 16u * 1024u * 1024u, 96u * 1024u, 8u * 1024u * 1024u,
                                        256, 256};

// What the radio layer and the boot code measure and hand over.
struct Measured {
  std::uint32_t flashBytes = 0;   // from the chip's flash id
  std::uint32_t flashSizeHz = 0;  // unused today, kept for the CAD/TCXO budget
  std::size_t heapFreeBytes = 0;  // freeHeap() after init, before capture starts
  std::size_t psramFreeBytes = 0; // 0 when the board has none
  std::uint8_t slots = 0;         // from the partition table in flash
  bool profimacro = false;        // WiFi/BLE stacks initialised and holding memory
};

enum class FitStatus : std::uint8_t {
  Ok = 0,
  FlashTooSmall,   // fewer slots fit than the layout declares
  HeapTooSmall,    // not enough RAM left for the working set
  PsramExpected,   // a PSRAM profile was selected but no PSRAM was found
  SlotTooSmall,    // the working set does not fit the app partition
};

const char* fitStatusName(FitStatus s);

struct MemoryReport {
  FitStatus status = FitStatus::Ok;
  std::size_t workingSetBytes = 0;   // exact, from sizeof
  std::size_t heapFreeBytes = 0;
  std::size_t heapRequiredBytes = 0; // working set plus headroom
  std::size_t slotBytes = 0;
  std::size_t slotUsedBytes = 0;
  std::size_t psramFreeBytes = 0;
  std::uint8_t slots = 0;
  std::uint8_t capacity = 0;
  std::uint16_t deviceCapacity = 0;
  std::uint16_t ringCapacity = 0;

  char detail[160] = {};

  bool ok() const { return status == FitStatus::Ok; }
};

// Headroom over the working set. The sniffer prints, mounts a filesystem and
// formats JSON lines; none of that is in `sizeof`. A tenth of free heap is not
// much to give away when the alternative is a device that works on the bench and
// fragments itself on a roof.
constexpr std::size_t kHeapHeadroomNumerator = 1;
constexpr std::size_t kHeapHeadroomDenominator = 8;

// The exact static footprint of one capture pipeline: engine, device table,
// counters, filter, the largest temporary record and a JSON line buffer.
//
// Every term is a real `sizeof`. There is nothing here to keep in step with the
// code, which is the entire reason the check can be trusted.
std::size_t workingSetBytes(std::uint16_t deviceCapacity, std::uint16_t ringCapacity);

// Required heap for a profile: working set plus headroom.
std::size_t heapRequired(std::uint16_t deviceCapacity, std::uint16_t ringCapacity,
                         std::size_t heapFreeBytes);

// Check the board against the layout and the profile.
//
// `appUsedBytes` is the firmware image size, which the linker knows and the boot
// code can read from the partition; it is separate from the working set because a
// 2 MB slot that cannot hold the image is a different failure from a 96 KB heap
// that cannot hold the buffers.
MemoryReport checkFit(const MemoryProfile& profile, const Measured& m, std::size_t appUsedBytes);

// Multi-line report for the boot log and for the console's `memory` command, which
// a host drives over serial with `sniffctl.py --send memory`. Fixed
// field order so two captures diff cleanly.
std::string renderMemory(const MemoryReport& r);

}  // namespace sniff
