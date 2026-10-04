// SPDX-License-Identifier: MIT
//
// The device list: two orderings, fixed capacity, and no allocation anywhere.
//
// The orderings are the point of this suite. `ShortestPath` and `LastSeen` are
// different questions and both were asked for, so the tests check each in isolation
// and then check that they disagree -- a test that passed for both would be a test
// that had accidentally implemented one of them twice.

#include <cstring>
#include <vector>

#include "harness.hpp"
#include "sniffer/Capture.hpp"
#include "sniffer/Console.hpp"
#include "sniffer/DeviceTable.hpp"

using namespace sniff;

namespace {

using Table = DeviceTable<8>;

void noteNode(Table* t, Protocol proto, std::uint8_t a, std::uint8_t b, std::uint8_t c,
              std::uint8_t d, bool hopsValid, std::uint8_t hops, std::uint32_t atMs) {
  const std::uint8_t id[4] = {a, b, c, d};
  t->observe(proto, proto == Protocol::Meshtastic ? Identity::MeshtasticNodeNum
                                                  : Identity::MeshCoreKeyPrefix,
             id, atMs);
  t->noteHops(proto, proto == Protocol::Meshtastic ? Identity::MeshtasticNodeNum
                                                    : Identity::MeshCoreKeyPrefix,
             id, hopsValid, hops);
}

}  // namespace

void suite_device_table() {
  harness::suite("DeviceTable");

  CHECK_EQ(Table().capacity(), 8u);
  CHECK_EQ(Table().size(), 0u);

  // --- identity is a pair, not just the id -------------------------------
  //
  // A four-byte id is not unique across protocols, and two communities sharing one
  // frequency is the premise of the whole hardware. These must be two rows.

  {
    Table t;
    const std::uint8_t same[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    t.observe(Protocol::MeshCore, Identity::MeshCoreKeyPrefix, same, 1000);
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, same, 1001);
    CHECK_MSG(t.size() == 2, "the same four bytes on two protocols are two different nodes");
  }
  {
    // Same protocol, different identity kind.
    Table t;
    const std::uint8_t same[4] = {1, 2, 3, 4};
    t.observe(Protocol::LoRaWan, Identity::LoRaWanDevEui, same, 1000);
    t.observe(Protocol::LoRaWan, Identity::LoRaWanDevAddr, same, 1001);
    CHECK_EQ(t.size(), 2u);
  }
  {
    // Genuinely the same node: counted once, frames accumulated.
    Table t;
    const std::uint8_t same[4] = {9, 8, 7, 6};
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, same, 1000);
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, same, 2000);
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, same, 3000);
    CHECK_EQ(t.size(), 1u);
    CHECK_EQ(t.at(0).frames, 3u);
    CHECK_EQ(t.at(0).firstSeenMs, 1000u);
    CHECK_EQ(t.at(0).lastSeenMs, 3000u);
  }

  // --- shortest-path ordering ---------------------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 5, 1000);
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 0, 1000);
    noteNode(&t, Protocol::Meshtastic, 3, 0, 0, 0, true, 2, 1000);
    noteNode(&t, Protocol::Meshtastic, 4, 0, 0, 0, true, 1, 1000);

    Device out[8];
    const std::size_t n = t.list(Order::ShortestPath, out, 8);
    REQUIRE(n == 4);
    CHECK_EQ(out[0].id[0], 2);  // zero hops
    CHECK_EQ(out[1].id[0], 4);  // one hop
    CHECK_EQ(out[2].id[0], 3);  // two hops
    CHECK_EQ(out[3].id[0], 1);  // five hops
  }
  {
    // Unknown distance sorts last, always. An unattributable frame has no path
    // field, which is not the same as being adjacent -- and putting unknown first
    // would be the default-looking answer.
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, false, 0, 1000);
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 3, 1000);
    noteNode(&t, Protocol::Meshtastic, 3, 0, 0, 0, false, 0, 1000);
    noteNode(&t, Protocol::Meshtastic, 4, 0, 0, 0, true, 1, 1000);

    Device out[8];
    const std::size_t n = t.list(Order::ShortestPath, out, 8);
    REQUIRE(n == 4);
    CHECK_EQ(out[0].id[0], 4);  // one hop: the closest known
    CHECK_EQ(out[1].id[0], 2);  // three hops: the furthest known
    CHECK_MSG(out[2].hopsValid == false, "then the two with unknown distance");
    CHECK(out[3].hopsValid == false);
  }
  {
    // The best hop count ever seen wins. A flood going the other way round must not
    // push a node down the list.
    Table t;
    const std::uint8_t id[4] = {5, 0, 0, 0};
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, 1000);
    t.noteHops(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, true, 4);
    CHECK_EQ(t.at(0).hops, 4);
    t.noteHops(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, true, 1);
    CHECK_MSG(t.at(0).hops == 1, "a shorter path improves the node's position");
    t.noteHops(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, true, 6);
    CHECK_MSG(t.at(0).hops == 1, "a longer sighting must not make it worse");
    t.noteHops(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, false, 0);
    CHECK_MSG(t.at(0).hops == 1, "an unknown path does not clear a known one");
  }

  // --- last-seen ordering ---------------------------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 0, 1000);
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 5, 1000);
    noteNode(&t, Protocol::Meshtastic, 3, 0, 0, 0, true, 3, 1000);

    Device out[8];
    std::size_t n = t.list(Order::LastSeen, out, 8);
    REQUIRE(n == 3);
    CHECK_MSG(out[0].id[0] == 1 && out[1].id[0] == 3 && out[2].id[0] == 2,
              "last-seen is newest first");

    // Something arrived a second ago: it must lead, even though it is the furthest
    // away. This is the case a hops-only ordering gets wrong.
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 5, 9000);
    n = t.list(Order::LastSeen, out, 8);
    REQUIRE(n == 3);
    CHECK_MSG(out[0].id[0] == 2, "a node that just started talking leads the recent list");

    n = t.list(Order::ShortestPath, out, 8);
    REQUIRE(n == 3);
    CHECK_MSG(out[0].id[0] == 1,
              "and the shortest-path list still leads with the adjacent node");
  }

  // --- the two orders genuinely differ -----------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 0, 9000);   // adjacent, old
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 7, 8000);   // distant, older
    Device byPath[8];
    Device bySeen[8];
    t.list(Order::ShortestPath, byPath, 8);
    t.list(Order::LastSeen, bySeen, 8);
    CHECK_MSG(byPath[0].id[0] != bySeen[0].id[0],
              "if both orders led with the same node one of them is not implemented");
  }

  // --- most-frames ordering -------------------------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 0, 1000);
    for (int i = 0; i < 5; ++i) noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 0, 1000);
    Device out[8];
    t.list(Order::MostFrames, out, 8);
    CHECK_MSG(out[0].id[0] == 2, "the loudest device leads the frames ordering");
  }

  // --- the ordering is total and therefore repeatable -----------------------

  {
    Table t;
    // Five nodes, all at hop 3, all heard at the same instant. Without a total
    // tiebreak the listing would depend on table layout and an operator comparing
    // two readings would see phantom movement.
    for (std::uint8_t i = 1; i <= 5; ++i) {
      noteNode(&t, Protocol::Meshtastic, i, 0, 0, 0, true, 3, 1000);
    }
    Device a[8];
    Device b[8];
    t.list(Order::ShortestPath, a, 8);
    t.list(Order::ShortestPath, b, 8);
    for (std::size_t i = 0; i < t.size(); ++i) {
      CHECK_MSG(a[i].id[0] == b[i].id[0], "the same table must list the same way twice");
    }
  }

  // --- eviction --------------------------------------------------------------

  {
    // Full table, then a ninth node. The slot with the oldest sighting goes, because
    // that is the node least likely to be heard again.
    Table t;
    for (std::uint8_t i = 1; i <= 8; ++i) {
      noteNode(&t, Protocol::Meshtastic, i, 0, 0, 0, true, 0, 1000 + i);
    }
    CHECK_EQ(t.size(), 8u);
    noteNode(&t, Protocol::Meshtastic, 99, 0, 0, 0, true, 0, 5000);
    CHECK_EQ(t.size(), 8u);

    bool oldGone = true;
    bool newPresent = false;
    for (std::size_t i = 0; i < t.size(); ++i) {
      if (t.at(i).id[0] == 1) oldGone = false;  // the 1001 ms sighting
      if (t.at(i).id[0] == 99) newPresent = true;
    }
    CHECK_MSG(oldGone, "the least recently seen node is the one evicted");
    CHECK(newPresent);
  }
  {
    // Size must not exceed capacity however many nodes turn up.
    Table t;
    for (std::uint16_t i = 0; i < 200; ++i) {
      const std::uint8_t id[4] = {static_cast<std::uint8_t>(i & 0xFF),
                                  static_cast<std::uint8_t>(i >> 8), 0, 0};
      t.observe(Protocol::MeshCore, Identity::MeshCoreKeyPrefix, id, i * 10);
    }
    CHECK_MSG(t.size() <= 8u, "the table never exceeds its capacity");
    CHECK_EQ(t.size(), 8u);
  }

  // --- reachability summaries -------------------------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 0, 1000);
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 1, 1000);
    noteNode(&t, Protocol::Meshtastic, 3, 0, 0, 0, true, 4, 1000);
    noteNode(&t, Protocol::Meshtastic, 4, 0, 0, 0, false, 0, 1000);

    CHECK_MSG(t.direct() == 1, "one node is adjacent");
    CHECK_EQ(t.withinHops(0), 1u);
    CHECK_EQ(t.withinHops(1), 2u);
    CHECK_EQ(t.withinHops(3), 2u);
    CHECK_EQ(t.withinHops(4), 3u);
    CHECK_MSG(t.withinHops(0, true) == 2,
              "asked to include unknown distance, an unknown node is counted as reachable");
  }
  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 3, 1000);
    noteNode(&t, Protocol::Meshtastic, 2, 0, 0, 0, true, 1, 5000);
    const Device* newest = t.newest();
    const Device* closest = t.closest();
    REQUIRE(newest != nullptr);
    REQUIRE(closest != nullptr);
    CHECK_EQ(newest->id[0], 2);
    CHECK_EQ(closest->id[0], 2);
  }
  {
    // An empty table has no newest and no closest, and must say so rather than
    // dereferencing something.
    Table t;
    CHECK(t.newest() == nullptr);
    CHECK(t.closest() == nullptr);
    CHECK_EQ(t.withinHops(7), 0u);
    CHECK_EQ(t.direct(), 0u);
  }

  // --- RSSI keeps the best ---------------------------------------------------

  {
    Table t;
    const std::uint8_t id[4] = {7, 0, 0, 0};
    t.observe(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, 1000);
    CHECK(!t.at(0).bestRssiValid);
    t.noteRssi(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, -110);
    CHECK(t.at(0).bestRssiValid);
    CHECK_EQ(t.at(0).bestRssiDbm, -110);
    t.noteRssi(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, -95);
    CHECK_MSG(t.at(0).bestRssiDbm == -95, "a better sighting replaces a worse one");
    t.noteRssi(Protocol::Meshtastic, Identity::MeshtasticNodeNum, id, -120);
    CHECK_MSG(t.at(0).bestRssiDbm == -95, "a worse sighting must not replace a better one");
  }

  // --- clear -----------------------------------------------------------------

  {
    Table t;
    noteNode(&t, Protocol::Meshtastic, 1, 0, 0, 0, true, 0, 1000);
    t.clear();
    CHECK_EQ(t.size(), 0u);
    CHECK(t.newest() == nullptr);
  }

  // --- names ------------------------------------------------------------------

  CHECK(std::strcmp(nodeRoleName(NodeRole::RoomServer), "room_server") == 0);
  CHECK(std::strcmp(nodeRoleName(NodeRole::Unknown), "unknown") == 0);
  CHECK(std::strcmp(identityName(Identity::MeshCoreKeyPrefix), "meshcore-key") == 0);
  CHECK(std::strcmp(identityName(Identity::FingerprintOnly), "opaque") == 0);
  CHECK(std::strcmp(orderName(Order::ShortestPath), "shortest-path") == 0);
  CHECK(std::strcmp(orderName(Order::LastSeen), "last-seen") == 0);

  // --- the size formula the memory check depends on ---------------------------

  {
    CHECK_MSG(deviceTableBytes(4) == 4 * sizeof(Device),
              "MemoryBudget relies on this being exact");
    CHECK_MSG(sizeof(Table) == 8 * sizeof(Device) + 16,
              "and on the template agreeing with it");
  }
}
