// SPDX-License-Identifier: MIT
//
// Beacon encoding, the transmit gate, and the command grammar.
//
// All three are here because all three can be wrong in ways that only show up on
// air. The frames built here are exactly the frames that would be transmitted, so
// the tests assert against the decoders in this repository as well as against the
// byte layouts -- an encoder and a decoder that agree with each other and disagree
// with the specification is a self-consistent bug, and checking the decoder catches
// the case where the encoder drifted.

#include <cstring>
#include <vector>

#include "harness.hpp"
#include "sniffer/Beacon.hpp"
#include "sniffer/CommandLine.hpp"
#include "sniffer/Filter.hpp"
#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/MeshCorePayload.hpp"
#include "sniffer/Record.hpp"
#include "sniffer/Provenance.hpp"
#include "sniffer/TxLockout.hpp"

using namespace sniff;

namespace {

// Parse a BeaconFrame as if it had come off the air.
meshcore::Packet parseMeshCore(const BeaconFrame& f) {
  return meshcore::parse(f.data, f.length, kMeshCoreSync, true);
}

}  // namespace

void suite_beacon() {
  harness::suite("Beacon");

  // --- the transmit gate ---------------------------------------------------
  //
  // This is the property the whole RX-only build rests on. It is asserted here
  // rather than left as a comment because a comment is not a test and this is the
  // claim an operator relies on.

  {
    CHECK_MSG(!mayTransmit(), "mayTransmit() is false regardless of build flags");
    CHECK_MSG(!TxLockout::permit(), "and so is TxLockout::permit()");
    CHECK(TxLockout::isRxOnly());
    CHECK(mayReceive());
    CHECK(usesCarrierSense());
    CHECK_MSG(kRxOnlyStatement[0] != '\0', "the statement printed at boot must exist");

    // The default build cannot transmit, full stop.
#if SNIFFER_TX_CAPABLE == 0
    CHECK_MSG(!mayEverTransmit(), "the default build has no transmit path at all");
    CHECK(std::strcmp(txModeName(), "rx-only") == 0);
    CHECK_MSG(std::strcmp(kBeaconStatement, "beacon build: transmit path compiled in but "
                                           "disarmed; it stays silent until armed") == 0,
              "the beacon statement names arming, because that is the gate");
#endif
  }
  {
    // Runtime arming starts disarmed, every boot. A device that comes back after a
    // power cut should be silent.
    BeaconTx::resetCounters();
    CHECK(!BeaconTx::isArmed());
    BeaconTx::armBeacon();
#if SNIFFER_TX_CAPABLE == 0
    CHECK_MSG(!BeaconTx::isArmed(),
              "arming an RX-only build must not enable transmission");
#else
    CHECK(BeaconTx::isArmed());
    CHECK(std::strcmp(txModeName(), "beacon-armed") == 0);
#endif
    CHECK_EQ(BeaconTx::emitted(), 0u);
    BeaconTx::countEmitted();
    CHECK_EQ(BeaconTx::emitted(), 1u);
    BeaconTx::resetCounters();
    CHECK_MSG(BeaconTx::emitted() == 0 && !BeaconTx::isArmed(), "reset disarms again");
  }

  // --- schedule clamping ----------------------------------------------------

  {
    BeaconSchedule s;
    s.count = 0;
    s.intervalMs = 0;
    CHECK(clampSchedule(&s));
    CHECK_MSG(s.count == 1, "zero repeats is not a beacon, and one still is");
    CHECK_MSG(s.intervalMs == kMinBeaconIntervalMs,
              "and the interval floor applies: a fast loop is a denial-of-service tool");

    s.count = 200;
    s.intervalMs = 5000;
    CHECK(clampSchedule(&s));
    CHECK_MSG(s.count == kMaxBeaconRepeats, "a runaway repeat count is capped");

    s.count = 5;
    s.intervalMs = 10000;
    CHECK(clampSchedule(&s));
    CHECK_MSG(s.count == 5 && s.intervalMs == 10000, "a legal schedule is left alone");
  }

  // --- MeshCore GRP_TXT -----------------------------------------------------

  {
    const BeaconFrame f = meshCoreGroupText(0x8F, "test beacon");
    CHECK(f.protocol == Protocol::MeshCore);
    CHECK_MSG(f.length == 4 + 11, "header + path length + flags + channel + text");
    CHECK_EQ(f.data[0], 0x15);  // v1, GRP_TXT, flood
    CHECK_EQ(f.data[1], 0x00);  // no path: flooded, so maximum reach

    // Round-trip through the decoder that has to read this on the other end.
    const meshcore::Packet p = parseMeshCore(f);
    REQUIRE(p.wellFormed);
    CHECK(p.payloadType == meshcore::PayloadType::GrpTxt);
    CHECK(p.routeType == meshcore::RouteType::Flood);
    CHECK_EQ(p.pathBytes, 0u);
    CHECK_EQ(p.payloadLength, 2u + 11u);  // flags + channel hash + the text itself

    const meshcore::Payload d =
        meshcore::decodePayload(p, f.data, /*plainText=*/true);
    REQUIRE(d.ok);
    CHECK(d.decoder == DecoderId::MeshCoreGroupText);
    CHECK_EQ(d.channelHash, 0x8F);
    CHECK_MSG(std::strcmp(d.text, "test beacon") == 0,
              "a beacon must read back as the message that was typed");
  }
  {
    // Empty text still produces a structurally valid frame; the CLI refuses to get
    // here, and the encoder refusing would be the second line of defence.
    const BeaconFrame f = meshCoreGroupText(0x00, "");
    CHECK(f.length >= 4);
    const meshcore::Packet p = parseMeshCore(f);
    REQUIRE(p.wellFormed);
  }
  {
    // Text longer than the bound is truncated rather than overflowing the frame.
    std::vector<char> big(kMaxBeaconText + 100, 'x');
    big[big.size() - 1] = '\0';
    const BeaconFrame f = meshCoreGroupText(0x11, big.data());
    CHECK(f.length <= kMaxFrameBytes);
    const meshcore::Packet p = parseMeshCore(f);
    REQUIRE(p.wellFormed);
    CHECK(p.payloadLength <= meshcore::kMaxPayloadBytes);
  }
  CHECK(describeBeacon(meshCoreGroupText(0x22, "hi")).find("MC beacon") == 0);
  CHECK(describeBeacon(meshCoreGroupText(0x22, "hi")).find("chan=0x22") != std::string::npos);
}

void suite_command_line() {
  harness::suite("CommandLine");

  // --- the verbs -------------------------------------------------------------

  {
    // Every verb must round-trip: parse(render(parse(line))) == parse(line).
    const char* verbs[] = {"help",  "stats", "memory",   "plan",  "filter", "devices",
                           "dump",  "tail", "hex",      "text",  "beacon", "arm",
                           "disarm", "emitted", "reset", "save", "load"};
    for (const char* v : verbs) {
      // `beacon` is the one verb with a required argument: bare, it is a usage error,
      // and it is checked on its own below. Asserting otherwise here would mean
      // inventing an empty beacon.
      const bool needsText = std::strcmp(v, "beacon") == 0;
      ParseResult r = parseCommand(v);
      CHECK_MSG(r.ok == !needsText, v);
      if (needsText) continue;

      CHECK_MSG(r.command.id != CommandId::None, v);

      // `hex`, `text` and `devices` normalise a bare invocation to their default rather
      // than leaving the argument empty, so the console can toggle without tracking
      // state. Every other verb takes nothing at all.
      const char* defaulted = (std::strcmp(v, "hex") == 0 || std::strcmp(v, "text") == 0)
                                  ? "toggle"
                                  : (std::strcmp(v, "devices") == 0 ? "shortest-path" : "");
      CHECK_MSG(std::strcmp(r.command.arg, defaulted) == 0, v);

      const std::string line = renderCommand(r.command);
      ParseResult again = parseCommand(line.c_str());
      CHECK_MSG(again.ok, line.c_str());
      CHECK_MSG(again.command.id == r.command.id, "a command must survive render/parse");
    }
  }
  {
    // Case-insensitive on the verb, because a phone keyboard has a shift key and
    // because serial monitors do odd things.
    ParseResult upper = parseCommand("STATS");
    ParseResult lower = parseCommand("stats");
    CHECK(upper.ok && lower.ok);
    CHECK(upper.command.id == lower.command.id);
  }
  {
    // A blank line is not an error. A serial monitor sends them constantly.
    ParseResult blank = parseCommand("");
    CHECK(blank.ok);
    CHECK(blank.command.id == CommandId::None);
    ParseResult spaces = parseCommand("   \r\n");
    CHECK(spaces.ok);
    CHECK(spaces.command.id == CommandId::None);
    ParseResult nul = parseCommand(nullptr);
    CHECK(!nul.ok);
  }

  // --- filter takes the whole remainder --------------------------------------

  {
    // One argument, not two: a filter spec with a space in it must survive.
    ParseResult r = parseCommand("filter untraceable=true, rssi<-90");
    REQUIRE(r.ok);
    CHECK(r.command.id == CommandId::Filter);
    CHECK_MSG(std::strcmp(r.command.arg, "untraceable=true, rssi<-90") == 0,
              "the filter spec is taken verbatim, spaces and all");

    // And it must be a spec the filter parser accepts, or the two grammars have
    // drifted apart.
    FilterSpec spec;
    char error[96];
    CHECK_MSG(parseFilter(r.command.arg, &spec, error, sizeof(error)),
              "a spec the console accepts must be a spec the filter understands");
    CHECK(spec.onlyUntraceable);
    CHECK(spec.hasRssi);
  }
  {
    ParseResult r = parseCommand("filter");
    REQUIRE(r.ok);
    CHECK_MSG(r.command.arg[0] == '\0', "filter with no argument clears to 'match everything'");
  }

  // --- devices ordering ------------------------------------------------------

  {
    ParseResult d = parseCommand("devices");
    REQUIRE(d.ok);
    CHECK(d.command.id == CommandId::Devices);
    CHECK_MSG(d.command.order == Order::ShortestPath, "the default ordering is shortest path");

    CHECK(parseCommand("devices last-seen").command.order == Order::LastSeen);
    CHECK(parseCommand("devices recent").command.order == Order::LastSeen);
    CHECK(parseCommand("devices frames").command.order == Order::MostFrames);
    CHECK(parseCommand("devices hops").command.order == Order::ShortestPath);

    ParseResult bad = parseCommand("devices sideways");
    CHECK(!bad.ok);
    CHECK_MSG(bad.error[0] != '\0', "a bad ordering is explained, not silently defaulted");
    CHECK(bad.command.id == CommandId::None);
  }

  // --- on/off switches --------------------------------------------------------

  {
    CHECK(std::strcmp(parseCommand("hex on").command.arg, "on") == 0);
    CHECK(std::strcmp(parseCommand("hex off").command.arg, "off") == 0);
    CHECK(std::strcmp(parseCommand("hex").command.arg, "toggle") == 0);
    CHECK(std::strcmp(parseCommand("text no").command.arg, "off") == 0);

    ParseResult bad = parseCommand("hex maybe");
    CHECK(!bad.ok);
    CHECK_MSG(std::strstr(bad.error, "on or off") != nullptr, "the accepted values are named");
  }

  // --- beacon ------------------------------------------------------------------

  {
    ParseResult r = parseCommand("beacon hello there both chan=8F n=5 ms=7000");
    REQUIRE(r.ok);
    CHECK(r.command.id == CommandId::Beacon);
    CHECK_MSG(std::strcmp(r.command.arg, "hello there") == 0,
              "the modifiers and the network selector are stripped from the text");
    CHECK(r.command.beaconOnMeshCore);
    CHECK(r.command.beaconOnMeshtastic);
    CHECK_EQ(static_cast<unsigned>(r.command.beaconChannel), 0x8Fu);
    CHECK_EQ(static_cast<unsigned>(r.command.beaconRepeats), 5u);
    CHECK_EQ(r.command.beaconIntervalMs, 7000u);

    ParseResult mc = parseCommand("beacon just mc");
    REQUIRE(mc.ok);
    CHECK_MSG(std::strcmp(mc.command.arg, "just") == 0, "mc is a selector, not part of the text");
    CHECK(mc.command.beaconOnMeshCore);
    CHECK_MSG(!mc.command.beaconOnMeshtastic,
              "MeshCore alone is the default; a beacon on an unnamed network is nobody's beacon");

    ParseResult mt = parseCommand("beacon hi mt");
    REQUIRE(mt.ok);
    CHECK(!mt.command.beaconOnMeshCore);
    CHECK(mt.command.beaconOnMeshtastic);

    ParseResult none = parseCommand("beacon both");
    CHECK(!none.ok);
    CHECK_MSG(std::strstr(none.error, "no text") != nullptr,
              "a beacon with only modifiers and no message is refused");

    ParseResult empty = parseCommand("beacon");
    CHECK(!empty.ok);

    ParseResult badChan = parseCommand("beacon hi chan=nope");
    CHECK(!badChan.ok);
    CHECK_MSG(std::strstr(badChan.error, "chan=") != nullptr, "a bad modifier names itself");

    ParseResult badRepeats = parseCommand("beacon hi n=lots");
    CHECK(!badRepeats.ok);
    CHECK(std::strstr(badRepeats.error, "n=") != nullptr);

    // A message that mentions a modifier-looking word survives, because only the
    // exact `key=value` shapes are eaten.
    ParseResult tricky = parseCommand("beacon send n=1 to me");
    REQUIRE(tricky.ok);
    CHECK(std::strcmp(tricky.command.arg, "send n=1 to me") == 0);
  }

  // --- multi-network planning ---------------------------------------------------

  {
    const BeaconTarget targets[] = {
        {Protocol::MeshCore, 0x8F},
        {Protocol::Meshtastic, 0x00},
    };
    BeaconSchedule sched;
    sched.count = 3;
    sched.intervalMs = 5000;

    BeaconFrame frames[8];
    const BeaconPlan plan = buildBeacon(targets, 2, "reach me", sched, frames, 8);
    CHECK_MSG(plan.built == 6, "3 repeats of 2 networks");
    CHECK_EQ(plan.skipped, 0u);
    CHECK(plan.reason[0] == '\0');

    // Target-major ordering: every network gets its first copy before any network
    // gets its second. A duty-cycle limit that stops the run halfway must still
    // have covered both networks.
    CHECK(frames[0].protocol == Protocol::MeshCore);
    CHECK(frames[1].protocol == Protocol::Meshtastic);
    CHECK(frames[2].protocol == Protocol::MeshCore);
    CHECK(frames[3].protocol == Protocol::Meshtastic);
    CHECK_MSG(frames[0].data[3] == 0x8F, "the MeshCore copy carries the requested channel");
    CHECK_MSG(frames[1].data[meshtastic::kHeaderBytes - 3] == 0x00,
              "the Meshtastic copy is on the primary channel");

    for (std::size_t i = 0; i < plan.built; ++i) {
      CHECK_MSG(std::memcmp(frames[i].data, frames[i].data, frames[i].length) == 0,
                "every copy is well formed");
      CHECK(frames[i].length > 0);
    }
  }
  {
    // A Meshtastic target on a non-primary channel has no plaintext form, so it is
    // skipped rather than producing a frame whose body is quietly wrong.
    const BeaconTarget targets[] = {{Protocol::Meshtastic, 0x42}};
    BeaconSchedule sched;
    BeaconFrame frames[4];
    const BeaconPlan plan = buildBeacon(targets, 1, "hi", sched, frames, 4);
    CHECK_MSG(plan.built == 0, "no plaintext body exists for an encrypted channel");
    CHECK_EQ(plan.skipped, 3u);
  }
  {
    // A buffer too small stops the run and says so, rather than overrunning it.
    const BeaconTarget targets[] = {{Protocol::MeshCore, 0x01}, {Protocol::Meshtastic, 0x00}};
    BeaconSchedule sched;
    sched.count = 5;
    BeaconFrame frames[3];
    const BeaconPlan plan = buildBeacon(targets, 2, "hi", sched, frames, 3);
    CHECK_EQ(plan.built, 3u);
    CHECK(plan.skipped > 0);
    CHECK_MSG(std::strstr(plan.reason, "buffer") != nullptr, "and the reason is stated");
  }
  {
    BeaconFrame frames[4];
    BeaconSchedule sched;
    BeaconTarget none[1] = {{Protocol::MeshCore, 0x01}};
    CHECK(buildBeacon(nullptr, 1, "hi", sched, frames, 4).built == 0);
    CHECK(buildBeacon(none, 0, "hi", sched, frames, 4).built == 0);
    CHECK(buildBeacon(none, 1, nullptr, sched, frames, 4).built == 0);
    CHECK(buildBeacon(none, 1, "", sched, frames, 4).built == 0);

// A default-constructed schedule already asks for repeats, so the zero case has to be
// stated rather than assumed.
BeaconSchedule zero;
zero.count = 0;
BeaconPlan p = buildBeacon(none, 1, "hi", zero, frames, 4);
CHECK_MSG(p.built == 1, "a zero repeat count still produces one beacon after clamping");
  }

  // --- the Meshtastic beacon reads back as a text message ----------------------

  {
    const BeaconFrame f = meshtasticText(0x1A2B3C4D, 0xFFFFFFFF, "leet speak");
    CHECK(f.protocol == Protocol::Meshtastic);

    const meshtastic::Header h = meshtastic::parse(f.data, f.length);
    REQUIRE(h.wellFormed);
    CHECK_EQ(h.from, 0x1A2B3C4Du);
    CHECK_EQ(h.toLowByte, 0xFF);
    CHECK_MSG(h.channelHash == meshtastic::kPrimaryChannelHash,
              "the beacon must be on the channel whose body is plaintext");

    const meshtastic::Data d =
        meshtastic::parseData(f.data + h.payloadOffset, h.payloadLength);
    REQUIRE(d.present);
    CHECK_EQ(d.from, 0x1A2B3C4Du);
    CHECK_EQ(d.to, 0xFFFFFFFFu);

    const meshtastic::Decoded dec = meshtastic::decodePlaintext(d);
    REQUIRE(dec.ok);
    CHECK_EQ(dec.portnum, 1u);
    CHECK_MSG(std::strcmp(dec.portNumLabel, "TEXT_MESSAGE_APP") == 0,
              "a node on the mesh must see this as an ordinary text message");
  }
}
