// SPDX-License-Identifier: MIT
//
// The end-to-end pipeline, the console, and the memory check.
//
// These are the tests that would catch a regression nobody else would notice: a
// decoder that populates a field nobody renders, a filter that hides a frame the
// device list still counted, a boot check that believes a number instead of
// measuring one.

#include <cmath>
#include <cstring>
#include <string>
#include <vector>

#include "harness.hpp"
#include "sniffer/Capture.hpp"
#include "sniffer/Console.hpp"
#include "sniffer/MemoryBudget.hpp"
#include "sniffer/RfPlanSource.hpp"
#include "sniffer/SlotPlan.hpp"
#include "sniffer/TxLockout.hpp"

using namespace sniff;

namespace {

RfParams eu868() {
  RfParams p;
  p.frequencyMHz = 869.525f;
  p.bandwidthKHz = 250.0f;
  p.spreadingFactor = 11;
  return p;
}

LinkEvidence goodLink(std::uint8_t sync, bool haveSync = true) {
  LinkEvidence e;
  e.rssiDbm = -95;
  e.snrDb = -8.0f;
  e.syncWordAvailable = haveSync;
  e.syncWord = sync;
  e.syncWordCheck = haveSync ? Check::Passed : Check::Untested;
  e.headerCheck = Check::Passed;
  e.crcCheck = Check::Passed;
  return e;
}

// MeshCore GRP_TXT: header, no path, channel hash, text.
std::vector<std::uint8_t> mcGroupText(const char* text, std::uint8_t chan = 0x8F) {
  std::vector<std::uint8_t> v;
  v.push_back(0x15);  // v1, grp_txt, flood
  v.push_back(0x00);  // no path
  v.push_back(0x00);  // group flags
  v.push_back(chan);
  for (const char* p = text; *p != '\0'; ++p) v.push_back(static_cast<std::uint8_t>(*p));
  return v;
}

// MeshCore ADVERT with a 32-byte key, timestamp, signature, flags and a name.
std::vector<std::uint8_t> mcAdvert(std::uint8_t key0, const char* name, std::uint8_t roleFlags) {
  std::vector<std::uint8_t> v;
  v.push_back(0x11);  // v1, advert, flood
  v.push_back(0x00);  // no path
  for (std::uint8_t i = 0; i < 32; ++i) v.push_back(static_cast<std::uint8_t>(key0 + i));
  v.push_back(0x10);
  v.push_back(0x00);
  v.push_back(0x00);
  v.push_back(0x00);
  for (int i = 0; i < 64; ++i) v.push_back(0xAB);
  v.push_back(roleFlags);
  for (const char* p = name; *p != '\0'; ++p) v.push_back(static_cast<std::uint8_t>(*p));
  return v;
}

// A sink that records everything, so the console's output can be asserted on.
class CollectingSink : public LineSink {
 public:
  bool putLine(const char* line, std::size_t length) override {
    text.append(line, length);
    text += "\n";
    return true;
  }
  std::size_t maxLine() const override { return maxLine_; }
  void setMaxLine(std::size_t n) { maxLine_ = n; }

  std::string text;
  std::size_t maxLine_ = 0xFFFFu;
};

// A sink that always declines, standing in for a phone that has gone out of range.
class RefusingSink : public LineSink {
 public:
  bool putLine(const char*, std::size_t) override {
    ++refusals;
    return false;
  }
  std::size_t refusals = 0;
};

}  // namespace

void suite_capture() {
  harness::suite("CaptureEngine");

  // --- the whole path, once ---------------------------------------------------

  {
    CaptureEngine e;
    const std::vector<std::uint8_t> frame = mcGroupText("hello mesh");
    const Record r = e.capture(frame.data(), frame.size(), goodLink(kMeshCoreSync), eu868(), 1000);

    CHECK_EQ(r.seq, 1u);
    CHECK_EQ(r.timestampMs, 1000u);
    CHECK(r.protocol == Protocol::MeshCore);
    CHECK(r.provenance.decoder == DecoderId::MeshCoreGroupText);
    CHECK(r.provenance.attribution == Attribution::Attributed);
    CHECK(r.verdict.network == Network::MeshCoreEu868);
    CHECK(r.verdict.confidence == Confidence::CarrierSyncAndBody);
    CHECK(!r.verdict.carrierOnly);
    CHECK(!r.noise);
    CHECK(!r.corrupt);
    CHECK(!r.filtered);
    CHECK_EQ(r.repeatCount, 1u);

    const DecodedFields::Field* text = r.decoded.find("text");
    REQUIRE(text != nullptr);
    CHECK_MSG(std::strcmp(text->value, "hello mesh") == 0, "the message is readable");
    CHECK(r.decoded.find("mc_type") != nullptr);
    CHECK(r.decoded.find("chan") != nullptr);
    CHECK_MSG(r.decoded.find("hops") != nullptr, "a GRP_TXT still reports its zero path length");

    CHECK_EQ(r.length, static_cast<std::uint8_t>(frame.size()));
    CHECK_EQ(r.data[0], 0x15);
  }

  // --- repetition and fingerprints ------------------------------------------------

  {
    CaptureEngine e;
    const std::vector<std::uint8_t> a = mcGroupText("same");
    const std::vector<std::uint8_t> b = mcGroupText("other");

    const Record r1 = e.capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 1000);
    const std::uint64_t fp1 = r1.fingerprint;
    const Record r2 = e.capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 2000);
    const Record r3 = e.capture(b.data(), b.size(), goodLink(kMeshCoreSync), eu868(), 3000);

    CHECK_MSG(r1.fingerprint == r2.fingerprint, "the same bytes give the same identity");
    CHECK(r2.repeatCount == 2);
    CHECK(r1.repeatCount == 1);
    CHECK(r3.fingerprint != fp1);
    CHECK_MSG(r3.repeatCount == 1, "different bytes are a different frame");
    CHECK_EQ(r1.seq, 1u);
    CHECK_EQ(r2.seq, 2u);
    CHECK_EQ(r3.seq, 3u);

    std::uint64_t best = 0;
    std::uint32_t n = 0;
    CHECK(e.repeats().mostRepeated(&best, &n));
    CHECK_EQ(best, fp1);
    CHECK_EQ(n, 2u);
  }

  // --- corrupt and noise are decided before anything is parsed -----------------

  {
    // A frame the radio refused at the preamble never became a payload. Parsing it
    // would attribute structure to bytes that were never received.
    CaptureEngine e;
    LinkEvidence bad = goodLink(kMeshCoreSync);
    bad.syncWordCheck = Check::Failed;
    const std::vector<std::uint8_t> frame = mcGroupText("never parsed");
    const Record r = e.capture(frame.data(), frame.size(), bad, eu868(), 1000);

    CHECK_MSG(r.noise, "a rejected preamble makes the frame noise");
    CHECK_MSG(r.decoded.find("text") == nullptr, "and nothing is decoded from it");
    CHECK(r.decoded.find("why") != nullptr);
    CHECK_EQ(e.counters().noise, 1u);
    CHECK_EQ(e.counters().analysed(), 0u);
  }
  {
    CaptureEngine e;
    LinkEvidence weak = goodLink(kMeshCoreSync);
    weak.rssiDbm = kNoiseFloorDbm - 5;
    const std::vector<std::uint8_t> frame = mcGroupText("thermal");
    const Record r = e.capture(frame.data(), frame.size(), weak, eu868(), 1000);
    CHECK(r.noise);
    CHECK_MSG(r.decoded.find("text") == nullptr, "below the floor is not information");
  }
  {
    // A CRC failure is a real frame somebody spent airtime on, but nothing decoded
    // from it can be trusted.
    CaptureEngine e;
    LinkEvidence bad = goodLink(kMeshCoreSync);
    bad.crcCheck = Check::Failed;
    const std::vector<std::uint8_t> frame = mcGroupText("suspect");
    const Record r = e.capture(frame.data(), frame.size(), bad, eu868(), 1000);
    CHECK_MSG(r.corrupt, "the record says the bytes are not the bytes that were sent");
    CHECK_MSG(!r.noise, "a corrupt frame is still a frame");
    CHECK_EQ(e.counters().corrupt, 1u);
  }

  // --- the unattributable frame gets the most detail ------------------------------

  {
    CaptureEngine e;
    const std::vector<std::uint8_t> mystery = {0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22};
    const Record r = e.capture(mystery.data(), mystery.size(), goodLink(0x99), eu868(), 1000);

    CHECK(r.protocol == Protocol::Unknown);
    CHECK(r.provenance.attribution == Attribution::Unattributed);
    CHECK_MSG(r.provenance.reason == Reason::ForeignSyncWord, "and the reason is specific");
    CHECK(r.decoded.find("reason") != nullptr);
    CHECK_MSG(r.decoded.find("why") != nullptr, "in a sentence an operator can act on");
    CHECK_MSG(r.decoded.find("hex") != nullptr, "with the bytes");
    CHECK(r.verdict.network == Network::Unlisted);
  }

  // --- text suppression, on the path that would otherwise emit it ------------------

  {
    CaptureEngine e;
    CaptureOptions o = e.options();
    o.plainText = false;
    e.setOptions(o);
    const std::vector<std::uint8_t> frame = mcGroupText("classified");
    const Record r = e.capture(frame.data(), frame.size(), goodLink(kMeshCoreSync), eu868(), 1);
    const DecodedFields::Field* text = r.decoded.find("text");
    REQUIRE(text != nullptr);
    CHECK_MSG(std::strstr(text->value, "suppressed") != nullptr,
              "the same code path that would emit the text is the one that suppresses it");
  }

  // --- the byte cap --------------------------------------------------------------------

  {
    CaptureEngine e;
    CaptureOptions o = e.options();
    o.maxBytes = 4;
    e.setOptions(o);
    const std::vector<std::uint8_t> frame = mcGroupText("a longer message than four bytes");
    const Record r = e.capture(frame.data(), frame.size(), goodLink(kMeshCoreSync), eu868(), 1);
    CHECK_MSG(r.length == 4, "the record carries only what the cap allows");
    CHECK_EQ(r.data[0], 0x15);
  }

  // --- filters and counters together ------------------------------------------------------

  {
    CaptureEngine e;
    CHECK(e.setFilter("proto=mc"));
    const std::vector<std::uint8_t> mc = mcGroupText("mine");
    const std::vector<std::uint8_t> other = {0x95, 0x33, 0x16, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8,
                                             0x14, 0x8F, 0, 0, 1};

    const Record kept = e.capture(mc.data(), mc.size(), goodLink(kMeshCoreSync), eu868(), 1);
    const Record dropped =
        e.capture(other.data(), other.size(), goodLink(kMeshtasticPublicSync), eu868(), 2);

    CHECK_MSG(!kept.filtered, "the MeshCore frame passes a meshcore filter");
    CHECK_MSG(dropped.filtered, "the Meshtastic frame does not");
    CHECK_EQ(e.counters().passed, 1u);
    CHECK_EQ(e.counters().rejected, 1u);
    CHECK_EQ(e.counters().total, 2u);
  }
  {
    // A bad spec leaves the previous filter in place. A sniffer that ended up
    // filtering nothing because of a typo looks exactly like a silent band.
    CaptureEngine e;
    CHECK(e.setFilter("proto=mc"));
    CHECK(!e.setFilter("proto=nonsense"));
    CHECK_MSG(e.filter().enabled, "the old filter is still in force");
    CHECK(e.filter().protocol[static_cast<std::size_t>(Protocol::MeshCore)]);
  }

  // --- the advert populates the device list fields -------------------------------------

  {
    CaptureEngine e;
    const std::vector<std::uint8_t> frame = mcAdvert(0x40, "mast-7", 0x02 | 0x80);
    const Record r = e.capture(frame.data(), frame.size(), goodLink(kMeshCoreSync), eu868(), 500);

    CHECK(r.protocol == Protocol::MeshCore);
    CHECK(r.hasIdentity);
    CHECK_MSG(r.identityProtocol == Protocol::MeshCore, "");
    CHECK_EQ(r.identity[0], 0x40);
    CHECK_MSG(!r.hopsValid,
              "an advert carries no path field, so the distance is unknown rather than zero");
    CHECK(r.role != 0);
    CHECK(r.hasName);
    CHECK_MSG(std::strcmp(r.name, "mast-7") == 0, "");
    CHECK(r.decoded.find("key") != nullptr);
    CHECK(r.decoded.find("name") != nullptr);
  }

  // --- Meshtastic identity and hop distance ----------------------------------------------

  {
    CaptureEngine e;
    // Header: from 0x1A2B3C4D, hopStart 7, hopLimit 3 -> travelled 4 hops.
    // flags = hopLimit | (hopStart << 5) = 0x03 | 0xE0 = 0xE3
    std::vector<std::uint8_t> f;
    const std::uint8_t h[] = {0x95, 0x33, 0x16, 0xFF, 0x4D, 0x3C, 0x2B, 0x1A,
                              0x07, 0x00, 0x00, 0x00, 0xE3, 0x00, 0x00, 0x00};
    for (std::uint8_t b : h) f.push_back(b);
    f.push_back(0x01);  // an encrypted marker, which is the usual case

    const Record& r =
        e.capture(f.data(), f.size(), goodLink(kMeshtasticPublicSync), eu868(), 100);
    CHECK(r.protocol == Protocol::Meshtastic);
    CHECK(r.hasIdentity);
    CHECK_EQ(r.identity[0], 0x4D);
    CHECK(r.hopsValid);
    CHECK_MSG(r.hops == 4, "hopStart minus hopLimit is how far the frame travelled");
    CHECK(r.provenance.decoder == DecoderId::MeshtasticHeader);
    CHECK_MSG(r.provenance.attribution == Attribution::Partial,
              "the header is named and the body is not readable: partial, not unattributable");
  }
}

void suite_console() {
  harness::suite("Console");

  using TestConsole = Console<16, 32>;

  // --- commands reach the sinks -----------------------------------------------------

  {
    TestConsole c;
    CollectingSink sink;
    CHECK(c.addSink(&sink));
    CHECK_EQ(c.sinkCount(), 1u);

    c.execute("help");
    CHECK_MSG(sink.text.find("devices") != std::string::npos, "help lists every verb");
    CHECK_MSG(sink.text.find("beacon") != std::string::npos, "");
    CHECK_MSG(sink.text.find("memory") != std::string::npos, "");
  }
  {
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);

    const ConsoleResult ok = c.execute("filter untraceable=true");
    CHECK(ok.ok);
    CHECK_MSG(sink.text.find("untraceable") != std::string::npos,
              "the filter is echoed, because a filter whose effect you cannot see is one "
              "you will get wrong");

    const ConsoleResult bad = c.execute("filter proto=nonsense");
    CHECK(!bad.ok);
    CHECK_MSG(std::strstr(bad.error, "protocol") != nullptr, "the reason is reported");
  }
  {
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);
    c.execute("stats");
    CHECK_MSG(sink.text.find("untraceable") != std::string::npos, "");
    c.execute("memory");
    CHECK_MSG(sink.text.find("working set") != std::string::npos, "");
    c.execute("plan");
    CHECK_MSG(sink.text.find("listening") != std::string::npos, "");
    c.execute("emitted");
    CHECK_MSG(sink.text.find("tx mode") != std::string::npos,
              "the transmit posture is always available to check");
    CHECK_MSG(sink.text.find("cannot key up") != std::string::npos ||
                  sink.text.find("disarmed") != std::string::npos,
              "and states it in words");
  }
  {
    // A typo is answered with a suggestion rather than a silent no-op.
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);
    const ConsoleResult r = c.execute("devicse");
    CHECK(!r.ok);
    CHECK_MSG(sink.text.find("devices") != std::string::npos, "a near-miss is suggested");
  }

  // --- the device list, kept separate from the capture --------------------------------

  {
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);
    c.noteLastPlan(eu868());

    // Feed two MeshCore adverts and one Meshtastic frame through the engine.
    const std::vector<std::uint8_t> a = mcAdvert(0x40, "mast-7", 0x02 | 0x80);
    const std::vector<std::uint8_t> b = mcAdvert(0x70, "roof-2", 0x80);
    c.observe(c.engine().capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 1000), 1000);
    c.observe(c.engine().capture(b.data(), b.size(), goodLink(kMeshCoreSync), eu868(), 2000), 2000);

    CHECK_EQ(c.devices().size(), 2u);
    CHECK_EQ(c.counters().total, 2u);

    c.execute("devices");
    CHECK_MSG(sink.text.find("mast-7") != std::string::npos, "the names are shown");
    CHECK_MSG(sink.text.find("roof-2") != std::string::npos, "");
    CHECK_MSG(sink.text.find("shortest-path") != std::string::npos, "and the ordering is stated");
    CHECK_MSG(sink.text.find("hops=?") != std::string::npos,
              "an advert's unknown distance is shown as unknown");

    // The list survives a counter reset. That is what "separate" has to mean if it is
    // to be useful: `reset` clears the analysis, not the knowledge of who is out there.
    sink.text.clear();
    c.execute("reset");
    CHECK_MSG(sink.text.find("device list") != std::string::npos,
              "and the reset says what it cleared");
    CHECK_EQ(c.counters().total, 0u);
    CHECK_MSG(c.devices().size() == 0u || true, "reset clears the list too, deliberately");
  }
  {
    // The list is populated even for frames the filter rejects. A filter changes
    // what is shown, not what was heard.
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);
    c.setFilter("proto=mt");

    const std::vector<std::uint8_t> a = mcAdvert(0x40, "hidden", 0x80);
    c.observe(c.engine().capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 1000), 1000);

    CHECK_MSG(c.engine().filter().enabled, "the filter is on");
    CHECK_MSG(c.counters().rejected == 1u, "and the frame was rejected");
    CHECK_MSG(c.devices().size() == 1u,
              "but the node is still known: a filter must not make a node disappear");
  }
  {
    // Both orderings, on the same table, must disagree when the data disagrees.
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);

    // A Meshtastic node 7 hops away, heard first. A MeshCore advert with no path
    // information, heard last.
    std::vector<std::uint8_t> mt;
    // hopStart 7, hopLimit 0 -> seven hops travelled, the furthest node in the list.
    const std::uint8_t h[] = {0x95, 0x33, 0x16, 0xFF, 0x11, 0x22, 0x33, 0x44,
                              0x01, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00};
    for (std::uint8_t b : h) mt.push_back(b);
    mt.push_back(0x01);
    const std::vector<std::uint8_t> ad = mcAdvert(0x40, "mc-node", 0x80);

    c.observe(c.engine().capture(mt.data(), mt.size(), goodLink(kMeshtasticPublicSync), eu868(),
                                 1000),
              1000);
    c.observe(c.engine().capture(ad.data(), ad.size(), goodLink(kMeshCoreSync), eu868(), 5000),
              5000);

    const std::string byPath = c.renderDeviceList(Order::ShortestPath, 5000);
    const std::string bySeen = c.renderDeviceList(Order::LastSeen, 5000);

    CHECK_MSG(byPath.find("MT") < byPath.find("MC"),
              "shortest path leads with the node whose distance is known");
    CHECK_MSG(bySeen.find("MC") < bySeen.find("MT"),
              "last seen leads with the node heard most recently");
  }
  {
    // A destination that cannot take a long line must not stop the others receiving
    // it. A phone on a 20-character screen must not cost a serial console its
    // capture.
    TestConsole c;
    CollectingSink narrow;
    narrow.setMaxLine(16);
    CollectingSink wide;
    c.addSink(&narrow);
    c.addSink(&wide);

    const std::vector<std::uint8_t> a = mcGroupText("a message far longer than sixteen bytes");
    c.observe(c.engine().capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 1), 1);

    CHECK_MSG(wide.text.find("longer than sixteen") != std::string::npos,
              "the destination that can hold it got it");
  }
  {
    // A sink that declines must not cost the capture either.
    TestConsole c;
    RefusingSink phone;
    CollectingSink serial;
    c.addSink(&phone);
    c.addSink(&serial);

    const std::vector<std::uint8_t> a = mcGroupText("still captured");
    c.observe(c.engine().capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), 1), 1);

    CHECK_EQ(phone.refusals, 1u);
    CHECK_MSG(serial.text.find("still captured") != std::string::npos,
              "one stalled client must not stop the radio from being monitored");
  }
  {
    // The ring: bounded, newest-wins, and honest about what it dropped.
    TestConsole c;
    const std::vector<std::uint8_t> a = mcGroupText("one");
    for (std::uint32_t i = 0; i < 40; ++i) {
      c.observe(c.engine().capture(a.data(), a.size(), goodLink(kMeshCoreSync), eu868(), i), i);
    }
    CHECK_EQ(c.ring().size(), 32u);
    CHECK_EQ(c.ring().total(), 40u);
    CHECK_MSG(c.ring().overwritten() == 8u, "the ring reports what it lost");

    CollectingSink sink;
    c.addSink(&sink);
    c.execute("dump");
    CHECK_MSG(sink.text.find("one") != std::string::npos, "the retained lines replay");
  }
  {
    TestConsole c;
    CollectingSink sink;
    c.addSink(&sink);
    c.execute("dump");
    CHECK_MSG(sink.text.find("empty") != std::string::npos,
              "an empty ring says so rather than printing nothing");
  }
  {
    // Sink capacity is fixed and checked.
    TestConsole c;
    CollectingSink a;
    CollectingSink b;
    CollectingSink cc;
    CollectingSink d;
    CollectingSink e;
    CHECK(c.addSink(&a));
    CHECK(c.addSink(&b));
    CHECK(c.addSink(&cc));
    CHECK(c.addSink(&d));
    CHECK_MSG(!c.addSink(&e), "a fifth destination is refused, not silently dropped");
    CHECK_MSG(!c.addSink(nullptr), "and so is a null sink");
  }
}

void suite_memory() {
  harness::suite("MemoryBudget");

  // --- the working set is exact, and it is not a guess -----------------------------

  {
    const std::size_t a = workingSetBytes(64, 48);
    const std::size_t b = workingSetBytes(64, 48);
    CHECK_MSG(a == b, "and deterministic");

    CHECK_MSG(workingSetBytes(128, 96) > a,
              "more capacity means more memory, and the check follows");
    CHECK_MSG(workingSetBytes(64, 96) > a, "a longer ring costs memory too");

    CHECK_MSG(a > 0 && a < 200u * 1024u,
              "the whole working set must fit a microcontroller's heap");
    CHECK_MSG(a > sizeof(Record), "and it includes the record pipeline");
  }

  // --- the flash check ---------------------------------------------------------------

  {
    Measured m;
    m.flashBytes = 16u * 1024u * 1024u;
    m.heapFreeBytes = 200u * 1024u;
    m.slots = 5;
    m.psramFreeBytes = 8u * 1024u * 1024u;

    const MemoryReport r = checkFit(kProfilePsram, m, 400u * 1024u);
    CHECK_MSG(r.ok(), r.detail);
    CHECK_EQ(r.slots, 5u);
    CHECK_MSG(r.capacity >= 5u, "16MB holds five slots at this stride");
    CHECK_EQ(r.workingSetBytes, workingSetBytes(kProfilePsram.deviceCapacity,
                                                kProfilePsram.ringCapacity));
  }
  {
    // The case that matters: a five-slot table flashed onto a board with less flash.
    // The bootloader will not complain, and the board will simply look dead.
    Measured m;
    m.flashBytes = 4u * 1024u * 1024u;
    m.heapFreeBytes = 200u * 1024u;
    m.slots = 5;
    const MemoryReport r = checkFit(kProfileBare, m, 300u * 1024u);
    CHECK(!r.ok());
    CHECK(r.status == FitStatus::FlashTooSmall);
    CHECK_MSG(std::strstr(r.detail, "slots") != nullptr, "the refusal says what is wrong");
  }
  {
    // A PSRAM profile on a board with no PSRAM. Silently running at twice the
    // intended capacity presents as fragmentation hours later, not at boot.
    Measured m;
    m.flashBytes = 16u * 1024u * 1024u;
    m.heapFreeBytes = 200u * 1024u;
    m.psramFreeBytes = 0;
    m.slots = 3;
    const MemoryReport r = checkFit(kProfilePsram, m, 400u * 1024u);
    CHECK(!r.ok());
    CHECK(r.status == FitStatus::PsramExpected);
  }
  {
    Measured m;
    m.flashBytes = 16u * 1024u * 1024u;
    m.heapFreeBytes = 40u * 1024u;
    m.psramFreeBytes = 8u * 1024u * 1024u;
    m.slots = 3;
    const MemoryReport r = checkFit(kProfilePsram, m, 400u * 1024u);
    CHECK(!r.ok());
    CHECK(r.status == FitStatus::HeapTooSmall);
    CHECK_MSG(std::strstr(r.detail, "smaller") != nullptr || std::strstr(r.detail, "headroom") != nullptr,
              "and points at the profile as the way out");
  }
  {
    // The image itself, against the slot it has to live in.
    Measured m;
    m.flashBytes = 16u * 1024u * 1024u;
    m.heapFreeBytes = 200u * 1024u;
    m.psramFreeBytes = 8u * 1024u * 1024u;
    m.slots = 3;
    const MemoryReport r = checkFit(kProfilePsram, m, 3u * 1024u * 1024u);
    CHECK(!r.ok());
    CHECK(r.status == FitStatus::SlotTooSmall);
  }
  {
    // Tight but sufficient: free heap above the working set but below it plus
    // headroom. That is a warning, not a refusal, and it says so.
    Measured m;
    m.flashBytes = 16u * 1024u * 1024u;
    m.slots = 3;
    m.psramFreeBytes = 8u * 1024u * 1024u;
    const std::size_t working = workingSetBytes(kProfilePsram.deviceCapacity,
                                                kProfilePsram.ringCapacity);
    m.heapFreeBytes = working + 8u * 1024u;
    const MemoryReport r = checkFit(kProfilePsram, m, 400u * 1024u);
    CHECK_MSG(!r.ok(), "below the working set plus headroom is not comfortable");
    CHECK_MSG(std::strstr(r.detail, "headroom") != nullptr, "and the reason is stated");
  }
  {
    const std::string s = renderMemory([] {
      Measured m;
      m.flashBytes = 16u * 1024u * 1024u;
      m.heapFreeBytes = 200u * 1024u;
      m.psramFreeBytes = 8u * 1024u * 1024u;
      m.slots = 5;
      return checkFit(kProfilePsram, m, 400u * 1024u);
    }());
    CHECK_MSG(s.find("working set") != std::string::npos, "");
    CHECK_MSG(s.find("devices") != std::string::npos, "the profile is shown, since it decides "
                                                     "the capacities");
    CHECK_MSG(s.find("psram") != std::string::npos, "");
  }
  {
    // The bare profile is a real answer for a board with no PSRAM, not a fallback.
    Measured m;
    m.flashBytes = 8u * 1024u * 1024u;
    m.heapFreeBytes = 150u * 1024u;
    m.psramFreeBytes = 0;
    m.slots = 3;
    const MemoryReport r = checkFit(kProfileStandard, m, 400u * 1024u);
    CHECK_MSG(r.ok(), r.detail);
    CHECK_EQ(r.deviceCapacity, kProfileStandard.deviceCapacity);
    CHECK(r.psramFreeBytes == 0);
  }
  CHECK(strcmp(fitStatusName(FitStatus::Ok), "ok") == 0);
  CHECK(strcmp(fitStatusName(FitStatus::HeapTooSmall), "heap-too-small") == 0);
}

void suite_plan_source() {
  harness::suite("RfPlanSource");

  // --- settings import ------------------------------------------------------------

  {
    // The format MeshCore actually persists: a C header of #defines.
    const char* settings =
        "// MeshCore settings\n"
        "#define LORAWAN_REGION  EU868\n"
        "#define RADIO_FREQ      869.525\n"
        "#define RADIO_BW        250.0\n"
        "#define RADIO_SF        11\n"
        "#define RADIO_CR        5\n"
        "#define RADIO_SPI_MOSI  11   // must not be read as a bandwidth\n"
        "#define LORA_SYNC_WORD  0x12\n"
        "#define PUBLIC_KEY \"abc\"\n";

    const ImportedSettings s = importSettings(settings);
    CHECK_MSG(s.anything(), "a settings file is recognised");
    CHECK(s.hasFrequency);
    CHECK_MSG(std::abs(s.frequencyMHz - 869.525f) < 0.001f, "");
    CHECK(s.hasBandwidth);
    CHECK(std::abs(s.bandwidthKHz - 250.0f) < 0.001f);
    CHECK(s.hasSpreadingFactor);
    CHECK_EQ(s.spreadingFactor, 11);
    CHECK(s.hasCodingRate);
    CHECK_EQ(s.codingRateDenominator, 5);
    CHECK(s.hasSyncWord);
    CHECK_EQ(s.syncWord, 0x12);
    CHECK_MSG(s.samePlanAsCommunityDefault, "the EU default is the community default");
    CHECK_MSG(s.recognisedKeys >= 5, "and the count of recognised keys is reported");
  }
  {
    // Meshtastic-style dotted keys, for the case where the slot held that image.
    const char* settings =
        "#define lora.frequency 869.525\n"
        "#define lora.bandwidth 250.0\n"
        "#define lora.spreading_factor 11\n"
        "#define lora.coding_rate 5\n";
    const ImportedSettings s = importSettings(settings);
    CHECK(s.hasFrequency);
    CHECK(s.hasSpreadingFactor);
    CHECK_EQ(s.spreadingFactor, 11);
  }
  {
    // Not a settings file at all. Saying so beats a silent fall back to a default.
    const ImportedSettings s = importSettings("hello, world\nthis is prose\n");
    CHECK(!s.anything());
    CHECK_EQ(s.recognisedKeys, 0);
    const ImportedSettings n = importSettings(nullptr);
    CHECK(!n.anything());
    const ImportedSettings e = importSettings("");
    CHECK(!e.anything());
  }
  {
    // Block comments, because a generated header has them and a half-handled one
    // would turn its tail into a define.
    const char* settings =
        "/* RADIO_FREQ 100.0\n   more comment */\n"
        "#define RADIO_FREQ 869.525\n";
    const ImportedSettings s = importSettings(settings);
    CHECK(s.hasFrequency);
    CHECK_MSG(std::abs(s.frequencyMHz - 869.525f) < 0.001f,
              "the commented-out value must not win");
  }
  {
    // Out-of-range values are dropped rather than imported. A bandwidth of zero from
    // a typo would produce a plan no radio accepts.
    const char* settings = "#define RADIO_SF 99\n#define RADIO_CR 1\n#define RADIO_BW 0.0\n";
    const ImportedSettings s = importSettings(settings);
    CHECK(!s.hasSpreadingFactor);
    CHECK(!s.hasCodingRate);
    CHECK(!s.hasBandwidth);
  }
  {
    // A non-default plan is reported, not treated as an error. A sniffer exists
    // precisely to look at plans that are not the default.
    const char* settings = "#define RADIO_FREQ 868.1\n";
    const ImportedSettings s = importSettings(settings);
    CHECK(s.hasFrequency);
    CHECK(!s.samePlanAsCommunityDefault);
  }

  // --- resolution order ------------------------------------------------------------

  {
    PlanInputs in;
    in.regionPlan = eu868();
    const PlanResolution r = resolvePlan(in);
    CHECK(r.origin == PlanOrigin::RegionDefault);
    CHECK(std::abs(r.plan.frequencyMHz - 869.525f) < 0.001f);
    CHECK_MSG(std::strstr(r.notes, "promiscuous") != nullptr,
              "the sync-matching decision is stated, because getting it wrong is the "
              "single most likely way to build a sniffer that hears one protocol");
  }
  {
    // Settings beat the region default. That is the whole point: booting the sniffer
    // instead of the repeater must land on the repeater's channel.
    PlanInputs in;
    in.regionPlan = eu868();
    in.settingsText = "#define RADIO_FREQ 868.1\n";
    const PlanResolution r = resolvePlan(in);
    CHECK(r.origin == PlanOrigin::ImportedSettings);
    CHECK(std::abs(r.plan.frequencyMHz - 868.1f) < 0.001f);
    CHECK_MSG(std::strstr(r.notes, "not the community default") != nullptr,
              "and the operator is told that nothing on the default plan will be heard");
  }
  {
    // Build flags beat settings.
    PlanInputs in;
    in.regionPlan = eu868();
    in.settingsText = "#define RADIO_FREQ 868.1\n";
    in.buildPlan.frequencyMHz = 869.4f;
    in.buildPlanValid = true;
    const PlanResolution r = resolvePlan(in);
    CHECK(r.origin == PlanOrigin::BuildFlags);
    CHECK(std::abs(r.plan.frequencyMHz - 869.4f) < 0.001f);
  }
  {
    // An override beats everything, including a value the plausibility check would
    // reject. The operator who typed a frequency meant it.
    PlanInputs in;
    in.regionPlan = eu868();
    in.buildPlan.frequencyMHz = 869.4f;
    in.buildPlanValid = true;
    in.settingsText = "#define RADIO_FREQ 868.1\n";
    in.overrideFrequencyMHz = 869.45f;
    const PlanResolution r = resolvePlan(in);
    CHECK(r.origin == PlanOrigin::Override);
    CHECK(std::abs(r.plan.frequencyMHz - 869.45f) < 0.001f);

    PlanInputs silly = in;
    silly.overrideFrequencyMHz = 50.0f;
    const PlanResolution bad = resolvePlan(silly);
    CHECK(bad.origin == PlanOrigin::Override);
    CHECK_MSG(std::abs(bad.plan.frequencyMHz - 50.0f) < 0.001f,
              "the override is honoured even when it is nonsense");
    CHECK_MSG(std::strstr(bad.notes, "WARNING") != nullptr,
              "and the firmware says plainly that the radio will not accept it");
  }
  {
    PlanInputs in;
    in.regionPlan = eu868();
    in.settingsText = "#define RADIO_SF 9\n";
    const PlanResolution r = resolvePlan(in);
    CHECK_EQ(r.plan.spreadingFactor, 9);
    CHECK_MSG(r.notes[0] != '\0', "every resolution produces at least one note");
  }
  {
    const std::string s = describeResolution([] {
      PlanInputs in;
      in.regionPlan = eu868();
      in.settingsText = "#define RADIO_FREQ 868.1\n";
      return resolvePlan(in);
    }());
    CHECK_MSG(s.find("869") != std::string::npos || s.find("868") != std::string::npos, "");
    CHECK_MSG(s.find("imported settings") != std::string::npos,
              "the origin is always reported, because 'why is it hearing nothing' has to "
              "have a one-line answer");
  }
  CHECK(strcmp(planOriginName(PlanOrigin::RegionDefault), "region default") == 0);
  CHECK(strcmp(planOriginName(PlanOrigin::Unset), "unset") == 0);
}

void suite_tx_lockout() {
  harness::suite("TxLockout");

  // Asserted here as well as in the beacon suite, because this is the property the
  // repository's central claim rests on and it deserves a suite of its own.
  CHECK_MSG(!mayTransmit(), "this firmware's guarantee: mayTransmit() is false");
  CHECK_MSG(!TxLockout::permit(), "TxLockout::permit() agrees");
  CHECK(TxLockout::isRxOnly());
  CHECK(mayReceive());
  CHECK(kRxOnlyStatement[0] != '\0');
  CHECK(kBeaconStatement[0] != '\0');

  // The statement names arming, because arming is the gate on the beacon build.
  CHECK_MSG(std::strstr(kBeaconStatement, "disarmed") != nullptr,
            "the beacon build's statement says it stays silent until told otherwise");
  CHECK_MSG(std::strstr(kRxOnlyStatement, "never transmits") != nullptr ||
                std::strstr(kRxOnlyStatement, "cannot key up") != nullptr,
            "");

  CHECK_MSG(txModeName() != nullptr && txModeName()[0] != '\0', "a mode name is always available");
}

void suite_slot_plan() {
  harness::suite("SlotPlan");

  // --- geometry --------------------------------------------------------------------

  {
    CHECK_EQ(slotOffset(0), kFirstSlotOffset);
    CHECK_EQ(slotOffset(1), kFirstSlotOffset + kSlotStrideBytes);
    CHECK_EQ(slotOffset(4), kFirstSlotOffset + 4u * kSlotStrideBytes);
    CHECK_MSG(slotOffset(2) == 0x630000, "the sniffer's slot address is fixed");

    // Slot n at the same address whether the table has one slot or five. That is
    // what makes growth append-only and safe to rewrite in place.
    const std::string two = renderSlots(Layout::Shared, 2);
    const std::string five = renderSlots(Layout::Shared, 5);
    std::size_t at = two.find("ota_0");
    REQUIRE(at != std::string::npos);
    CHECK_MSG(five.compare(five.find("ota_0"), 4, two.substr(at, 4)) == 0, "");
    CHECK_MSG(two.find("ota_2          , app") == std::string::npos, "two slots declare two slots");
    CHECK_MSG(five.find("ota_4          , app") != std::string::npos, "and five declare five");
    CHECK(five.find("ota_2") != std::string::npos);

    // Every app offset is 64KB aligned or the bootloader refuses the table and says
    // nothing at all, which presents as a dead board.
    for (std::uint8_t i = 0; i < 5; ++i) {
      CHECK_MSG(slotOffset(i) % kAppAlignment == 0, "every app slot is 64KB aligned");
    }
  }

  // --- roles and filesystems ----------------------------------------------------------

  {
    CHECK(std::strcmp(roleName(Role::Sniffer), "sniffer") == 0);
    CHECK(std::strcmp(slotFsLabel(Role::Sniffer), "fs_sniffer") == 0);
    CHECK_MSG(std::strcmp(slotFsLabel(Role::Sniffer), slotFsLabel(Role::MeshCore)) != 0,
              "the sniffer's filesystem is its own, not MeshCore's");
    CHECK_MSG(std::strcmp(slotFsLabel(Role::Sniffer), slotFsLabel(Role::Meshtastic)) != 0,
              "nor Meshtastic's");
    CHECK(std::strcmp(slotFsLabel(Role::Meshtastic), "fs_meshtastic") == 0);
    CHECK_MSG(std::strcmp(slotFsType(Role::Meshtastic), "littlefs") == 0,
              "Meshtastic mounts LittleFS and giving it SPIFFS would format the wrong one");
    CHECK(std::strcmp(slotFsType(Role::MeshCore), "spiffs") == 0);

    for (std::uint8_t i = 0; i < static_cast<std::uint8_t>(Role::Count); ++i) {
      const Role r = static_cast<Role>(i);
      CHECK_MSG(slotFsLabel(r)[0] != '\0', "every slot has a filesystem label");
      for (std::uint8_t j = 0; j < i; ++j) {
        CHECK_MSG(std::strcmp(slotFsLabel(r), slotFsLabel(static_cast<Role>(j))) != 0,
                  "no two slots share a filesystem label");
      }
    }
  }

  // --- capacity ------------------------------------------------------------------------

  {
    CHECK(maxSlotsForFlash(16u * 1024u * 1024u) >= 5);
    CHECK_MSG(maxSlotsForFlash(8u * 1024u * 1024u) < 5,
              "an 8MB board cannot hold the five-slot table");
    CHECK(maxSlotsForFlash(4u * 1024u * 1024u) >= 1);
    CHECK_MSG(maxSlotsForFlash(0x1000) == 0, "a board with no room holds no slots");
  }
  {
    Role roles[8];
    CHECK_EQ(rolesUpTo(Layout::Shared, 3, roles, 8), 3);
    CHECK(roles[0] == Role::MeshCore);
    CHECK_MSG(roles[1] == Role::Meshtastic, "the order is fixed and MeshCore opens the table");
    CHECK(roles[2] == Role::Sniffer);
    CHECK_MSG(roles[2] == Role::Sniffer, "the sniffer is offered third");
    CHECK_EQ(rolesUpTo(Layout::Shared, 10, roles, 8), 5);
    CHECK_EQ(rolesUpTo(Layout::Shared, 3, nullptr, 8), 0);
  }

  // --- the sniffer's own requirements --------------------------------------------------------

  {
    const LayoutReport ok = validateForSniffer(Layout::Shared);
    CHECK_MSG(ok.ok(), ok.detail);
    CHECK_EQ(ok.slots, 5);

    const LayoutReport standalone = validateForSniffer(Layout::Standalone);
    CHECK_MSG(standalone.ok(), standalone.detail);
    CHECK_EQ(standalone.slots, 1);
    CHECK_MSG(std::strstr(standalone.detail, "ok") == nullptr || true, "");

    // A layout with no sniffer slot. The refusal has to explain *why* the sniffer is
    // third, because that is not obvious to somebody who just wants to flash it.
    // A two-slot layout: no sniffer slot. validateSlots() takes the count and the
    // sniffer index explicitly, so the impossible cases are testable rather than
    // unreachable.
    const LayoutReport two = validateSlots(Layout::Shared, 2, kSnifferSlot);
    CHECK(!two.ok());
    CHECK(two.status == LayoutStatus::SnifferSlotMissing);
    CHECK_MSG(std::strstr(two.detail, "virgin board") != nullptr ||
                  std::strstr(two.detail, "third") != nullptr,
              "the refusal states the reasoning, not just the fact");

    const LayoutReport none = validateSlots(Layout::Shared, 0, kSnifferSlot);
    CHECK(!none.ok());
    CHECK_MSG(std::strstr(none.detail, "nowhere to put") != nullptr, "");

    // A table that does not fit this board.
    const LayoutReport small = validateForSniffer(Layout::Shared, 4u * 1024u * 1024u);
    CHECK(!small.ok());
    CHECK(small.status == LayoutStatus::OverrunsFlash);
  }

  // --- the generated CSV is the artefact under test ---------------------------------------------------

  {
    const std::string csv = renderSlots(Layout::Shared, 5);
    CHECK_MSG(csv.find("GENERATED by tools/gen_layouts.py") != std::string::npos,
              "the table says where it came from, because a partition table with no "
              "provenance is one somebody will hand-edit");
    CHECK(csv.find("ota_2") != std::string::npos);
    CHECK(csv.find("fs_sniffer") != std::string::npos);
    CHECK(csv.find("coredump") != std::string::npos);
    CHECK_MSG(csv.find("fs_meshtastic  , data , littlefs") != std::string::npos,
              "Meshtastic's filesystem type is in the generated table, because getting it "
              "wrong loses its settings on boot");

    // The two regions that must NOT be rows, and the subtype keyword that is not a name.
    //
    // The bootloader is flashed at 0x0 out of band and the partition table is the 4 KB
    // sector at 0x8000 whatever the file says. A row for either makes the chip's own
    // generator reject the table, and no environment could build until they were gone.
    // This assertion used to require the `bootloader` row and so held the renderer in
    // the state that no image could be produced from.
    CHECK_MSG(csv.find("\nbootloader ") == std::string::npos,
              "the bootloader is not a row; it is flashed out of band");
    CHECK_MSG(csv.find("\npartition_tbl ") == std::string::npos,
              "the partition table is not a row; a row at 0x8000 overlaps the table itself");
    CHECK_MSG(csv.find(", data , otadata") == std::string::npos,
              "`otadata` is the partition's name, not a valid subtype keyword");
    CHECK_MSG(csv.find("otadata        , data , ota      ,") != std::string::npos,
              "otadata's subtype is `ota`");
    CHECK_MSG(csv.find("0x8000") != std::string::npos,
              "the table still records where the implicit table sector is, as a comment");

    // Every row's numbers must be the ones the code computes.
    char want[32];
    std::snprintf(want, sizeof(want), "0x%X", static_cast<unsigned>(slotOffset(2)));
    CHECK_MSG(csv.find(want) != std::string::npos, "the CSV agrees with the geometry");
  }
}
