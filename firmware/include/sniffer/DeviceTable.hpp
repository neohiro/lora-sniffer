// SPDX-License-Identifier: MIT
//
// DeviceTable -- the separate list of *nodes*, as opposed to the stream of frames.
//
// The brief asks for a device list kept apart from the capture, ordered two ways:
// by shortest path first, and by last seen. Both are wanted for different reasons
// and neither replaces the other:
//
//   * **Shortest path first** is how you find the interesting node. A repeater
//     three hops away that you can hear directly is worth more attention than the
//     one you can only hear through two other people. It is also the only ordering
//     that means anything as a graph, because on a flooding mesh hop count *is* the
//     distance.
//
//   * **Last seen first** is how you find the node that just arrived. Sorted by
//     hops, a beacon that started talking a second ago lands behind every device
//     you heard an hour ago and disappears.
//
// So both orderings are available over one table, and the ordering used is a
// property of the accessor rather than of the storage: nothing is ever re-sorted,
// which matters because re-sorting a table on a microcontroller means either an
// allocation or a hand-written insertion sort, and both are worse than picking an
// order when someone asks for a list.
//
// Identity, which is the subtle part. Three different protocols name nodes three
// different ways, and the table has to hold all of them without pretending they are
// the same thing:
//
//   * MeshCore nodes are Ed25519 public keys, 32 bytes. Identified by their first
//     4 bytes, which is what the firmware itself uses as a node "hash" -- full
//     32 bytes per entry would cost eight times the memory for no added value at
//     this range, and that trade is made explicitly rather than by accident.
//   * Meshtastic nodes are 4-byte node numbers. That fits exactly.
//   * LoRaWAN devices have an 8-byte DevEUI and a 4-byte DevAddr, neither of which
//     is the other, so both are stored.
//
// A 4-byte id is not unique across protocols, so every entry also carries its
// protocol and the pair is the key. Two communities on one frequency are the whole
// premise of this hardware.
//
// Everything is fixed capacity and inline. `capacity` is a template parameter
// rather than a runtime value precisely so the table can live in static memory and
// `sizeof(DeviceTable<N>)` is exact -- which is what lets MemoryBudget's boot check
// be a compile-time number.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"

namespace sniff {

// A node id, sized to hold any of the three. Four bytes is MeshCore's own node
// hash width and Meshtastic's node number width; the full key stays in the frame
// that carried it, and the capture keeps it.
constexpr std::size_t kDeviceIdBytes = 4;

// How a node was named, which is not always the protocol: a frame that was
// unattributable can still contribute an opaque blob to the list, marked as such,
// so the operator can see "something with this fingerprint is out there" without
// this file pretending it knows what it is.
enum class Identity : std::uint8_t {
  MeshCoreKeyPrefix = 0,
  MeshtasticNodeNum = 1,
  LoRaWanDevEui = 2,
  LoRaWanDevAddr = 3,
  FingerprintOnly = 4,
};

const char* identityName(Identity i);

// A node's role, where the protocol says. Unknown is a real answer and is the
// common one: a MeshCore GRP_TXT names no sender, only a channel.
enum class NodeRole : std::uint8_t {
  Unknown = 0,
  Chat,
  Repeater,
  RoomServer,
  Sensor,
  Companion,
  Gateway,
};

const char* nodeRoleName(NodeRole r);

struct Device {
  bool used = false;

  Protocol protocol = Protocol::Unknown;
  Identity identity = Identity::FingerprintOnly;
  std::uint8_t id[kDeviceIdBytes] = {};

  // Graph distance, from whichever field the protocol exposes. MeshCore encodes it
  // in the path hop count; Meshtastic in the header's hop limit. `hopsValid` is
  // separate because a node heard on a direct path is hop 0 and a node heard in a
  // frame with no path field at all is *unknown*, not zero -- and treating unknown
  // as zero would put every unlocatable node at the top of a shortest-path sort.
  std::uint8_t hops = 0;
  bool hopsValid = false;

  // kFingerprintTableClock is monotonic within a boot. Two devices must not share
  // it; a node seen at two times needs a tiebreak, and last-seen is the honest one.
  std::uint32_t firstSeenMs = 0;
  std::uint32_t lastSeenMs = 0;
  std::uint32_t frames = 0;

  std::uint8_t role = static_cast<std::uint8_t>(NodeRole::Unknown);

  // The strongest protocol verdict this node's frames have earned. A node that has
  // only ever been seen in a frame nothing could read stays Unattributed, which is
  // exactly the row an operator is looking for.
  Attribution attribution = Attribution::Unattributed;

  // Best RSSI this node has been heard at. Shown as a bar, because "how well can I
  // hear this one" is a question the hop count cannot answer. `bestRssiValid` is
  // separate for the same reason `hopsValid` is: a node recorded from a replayed
  // ring entry has no RSSI, which is not the same as 0 dBm.
  std::int16_t bestRssiDbm = 0;
  bool bestRssiValid = false;

  // A name, when one frame carried one. Bounded, because it came off the air.
  static constexpr std::size_t kNameBytes = 24;
  char name[kNameBytes] = {};
  bool hasName = false;

  // Text of the most recent message from this node, when the protocol had one.
  static constexpr std::size_t kTextBytes = 48;
  char lastText[kTextBytes] = {};
  bool hasText = false;
};

// How a listing should be ordered. Two orders, because the brief asks for both.
enum class Order : std::uint8_t {
  // Shortest path first. Nodes whose distance is unknown sort *after* every node
  // whose distance is known -- see Device::hopsValid.
  ShortestPath = 0,
  // Most recently heard first.
  LastSeen = 1,
  // Most frames first. Not asked for, and included anyway because "which device is
  // the loudest on this frequency" is the first question of a second kind.
  MostFrames = 2,
};

const char* orderName(Order o);

template <std::size_t kCapacity>
class DeviceTable {
 public:
  static_assert(kCapacity > 0, "a device table with no capacity is a bug, not a configuration");

  void clear() {
    for (std::size_t i = 0; i < kCapacity; ++i) entries_[i] = Device{};
    count_ = 0;
  }

  std::size_t capacity() const { return kCapacity; }
  std::size_t size() const { return count_; }
  const Device& at(std::size_t i) const { return entries_[i < kCapacity ? i : 0]; }

  // One sighting. Returns the entry, updated.
  //
  // A new node takes a free slot; when there are none, the slot whose last-seen
  // clock is oldest is replaced. That is LRU and it is the right policy here: the
  // node you have not heard from in the longest time is the one you are least
  // likely to be about to hear again, and evicting anything else would drop a node
  // that is still active.
  Device& observe(Protocol protocol, Identity identity, const std::uint8_t* id,
                  std::uint32_t nowMs) {
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) continue;
      if (entries_[i].protocol != protocol) continue;
      if (entries_[i].identity != identity) continue;
      if (!sameId(entries_[i].id, id)) continue;
      entries_[i].lastSeenMs = nowMs;
      ++entries_[i].frames;
      return entries_[i];
    }

    std::size_t victim = kCapacity;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) {
        victim = i;
        break;
      }
    }
    if (victim == kCapacity) {
      victim = 0;
      for (std::size_t i = 1; i < kCapacity; ++i) {
        if (entries_[i].lastSeenMs < entries_[victim].lastSeenMs) victim = i;
      }
      if (count_ < kCapacity) ++count_;
    }

    Device& d = entries_[victim];
    d = Device{};
    d.used = true;
    d.protocol = protocol;
    d.identity = identity;
    for (std::size_t i = 0; i < kDeviceIdBytes; ++i) d.id[i] = id != nullptr ? id[i] : 0;
    d.firstSeenMs = nowMs;
    d.lastSeenMs = nowMs;
    d.frames = 1;
    return d;
  }

  // Record the graph distance for a node, keeping the best (shortest) ever seen.
  // A frame that arrives by a longer route afterwards -- a flood going the other
  // way -- must not push a node down the shortest-path list.
  void noteHops(Protocol protocol, Identity identity, const std::uint8_t* id, bool hopsValid,
                std::uint8_t hops) {
    Device& d = observe(protocol, identity, id, 0);
    if (!hopsValid) return;
    if (!d.hopsValid || hops < d.hops) {
      d.hops = hops;
      d.hopsValid = true;
    }
  }

  void noteRssi(Protocol protocol, Identity identity, const std::uint8_t* id, std::int16_t rssi) {
    Device& d = observe(protocol, identity, id, 0);
    if (!d.bestRssiValid || rssi > d.bestRssiDbm) {
      d.bestRssiDbm = rssi;
      d.bestRssiValid = true;
    }
  }

  // The entries in the requested order, capped at `max`. Copies into a
  // caller-provided array so the caller owns the memory and nothing is allocated.
  //
  // Selection sort with a taken-mask: O(n^2) over at most 256 entries, which on a
  // microcontroller is a few thousand comparisons done once per command rather
  // than a sort that would need scratch memory.
  std::size_t list(Order order, Device* out, std::size_t max) const {
    std::size_t n = 0;
    bool taken[kCapacity] = {};
    while (n < max && n < count_) {
      std::size_t best = kCapacity;
      for (std::size_t i = 0; i < kCapacity; ++i) {
        if (!entries_[i].used || taken[i]) continue;
        if (best == kCapacity || better(entries_[i], entries_[best], order)) best = i;
      }
      if (best == kCapacity) break;
      taken[best] = true;
      out[n] = entries_[best];
      ++n;
    }
    return n;
  }

  // How many nodes are reachable within `maxHops`. The number an operator reads
  // first: "I can see nine nodes, four of them directly".
  std::size_t withinHops(std::uint8_t maxHops, bool includeUnknown = false) const {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) continue;
      if (!entries_[i].hopsValid) {
        if (includeUnknown) ++n;
        continue;
      }
      if (entries_[i].hops <= maxHops) ++n;
    }
    return n;
  }

  // How many are directly reachable, hop count zero. Kept as its own function
  // because it is the number that tells you whether the sniffer has a usable view
  // of the mesh at all.
  std::size_t direct() const {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (entries_[i].used && entries_[i].hopsValid && entries_[i].hops == 0) ++n;
    }
    return n;
  }

  // The newest node, for "something just appeared".
  const Device* newest() const {
    const Device* best = nullptr;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used) continue;
      if (best == nullptr || entries_[i].lastSeenMs > best->lastSeenMs) best = &entries_[i];
    }
    return best;
  }

  // The closest node, for "who can I reach".
  const Device* closest() const {
    const Device* best = nullptr;
    for (std::size_t i = 0; i < kCapacity; ++i) {
      if (!entries_[i].used || !entries_[i].hopsValid) continue;
      if (best == nullptr || entries_[i].hops < best->hops) best = &entries_[i];
    }
    return best;
  }

 private:
  static bool sameId(const std::uint8_t* a, const std::uint8_t* b) {
    if (a == nullptr || b == nullptr) return false;
    for (std::size_t i = 0; i < kDeviceIdBytes; ++i) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  // The comparator. Every ordering rule in the table lives here, which is what makes
  // "why is this node above that one" a one-function question.
  static bool better(const Device& a, const Device& b, Order order) {
    switch (order) {
      case Order::LastSeen:
        if (a.lastSeenMs != b.lastSeenMs) return a.lastSeenMs > b.lastSeenMs;
        break;

      case Order::MostFrames:
        if (a.frames != b.frames) return a.frames > b.frames;
        break;

      case Order::ShortestPath:
      default:
        // Unknown distance sorts last, always. Putting it first would be the
        // default-looking answer and it would be a lie: an unattributed frame has
        // no path field, which is not the same as being adjacent.
        if (a.hopsValid != b.hopsValid) return b.hopsValid;
        if (a.hopsValid && a.hops != b.hops) return a.hops < b.hops;
        break;
    }

    // Every ordering falls back to the same tiebreak: the node heard most recently
    // wins, then the node with the lower id. Both are total orders, so the listing
    // is deterministic -- which matters when an operator reads the same list twice
    // and expects the same answer.
    if (a.lastSeenMs != b.lastSeenMs) return a.lastSeenMs > b.lastSeenMs;
    for (std::size_t i = kDeviceIdBytes; i > 0; --i) {
      if (a.id[i - 1] != b.id[i - 1]) return a.id[i - 1] < b.id[i - 1];
    }
    return false;
  }

  Device entries_[kCapacity];
  std::size_t count_ = 0;
};

// The exact size of a table of a given capacity, for the boot-time memory check.
//
// A function rather than a template because MemoryBudget takes capacity as a
// runtime value from the profile. The `static_assert` below is what stops the
// function and the class disagreeing -- and it is written against a *measured*
// sizeof rather than a guessed padding figure, because a guess here would be a
// memory check that lies by however many bytes the compiler chose to insert.
inline std::size_t deviceTableBytes(std::size_t capacity) {
  return capacity * sizeof(Device) + (sizeof(DeviceTable<1>) - sizeof(Device));
}

static_assert(sizeof(DeviceTable<1>) - sizeof(Device) == sizeof(std::size_t),
              "a DeviceTable<1> must be its entries plus exactly one counter");
static_assert(sizeof(DeviceTable<4>) - sizeof(DeviceTable<1>) == 3 * sizeof(Device),
              "capacity must add exactly the entries, with no per-capacity padding");

}  // namespace sniff
