// SPDX-License-Identifier: MIT
//
// Console -- the command layer, portable, and the only place output is shaped.
//
// Everything above this file decides *what happened*. This file decides what the
// operator sees about it, and it does so for a serial terminal, a phone's BLE
// client and a desktop tool at the same time, from one set of renderers. That is
// what makes the "one grammar, three transports" claim true rather than aspirational.
//
// The device list is the centre of this file, because the brief asks for it to be
// **separate** from the capture: not a `grep` over the log, not a filter, its own
// structure with its own command and its own two orderings. Held here rather than in
// the capture engine so that a device list survives a cleared counter set and a
// cleared ring, which is what "separate" has to mean if it is to be useful at all.
//
// Sizing is the other thing this file is careful about. `Console` is templated on
// both capacities so that every table inside it lives in static memory and
// `sizeof(Console<N, M>)` is exact -- which is the number MemoryBudget checks at
// boot. There is no heap anywhere in this path.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "sniffer/Capture.hpp"
#include "sniffer/CommandLine.hpp"
#include "sniffer/Counters.hpp"
#include "sniffer/DeviceTable.hpp"
#include "sniffer/Jsonl.hpp"
#include "sniffer/MemoryBudget.hpp"
#include "sniffer/Record.hpp"
#include "sniffer/Transport.hpp"
#include "sniffer/TxLockout.hpp"

namespace sniff {

// What a command produced, so a caller can log it or show it.
struct ConsoleResult {
  bool ok = false;
  std::uint8_t linesOut = 0;
  char error[96] = {};
};

// A renderer for one destination. The serial console, an OLED and a phone client all
// want the same information in different shapes, and the difference is a callback.
class LineSink {
 public:
  virtual ~LineSink() = default;
  virtual bool putLine(const char* line, std::size_t length) = 0;
  // Some destinations cannot take a 300-byte line. They say no, the console moves on,
  // and no destination blocks another.
  virtual std::size_t maxLine() const { return 0xFFFFu; }
};

template <std::size_t kDevices, std::size_t kRing>
class Console {
 public:
  static_assert(kDevices > 0, "the device list needs a capacity");
  static_assert(kRing > 0, "the capture ring needs a capacity");

  CaptureEngine& engine() { return engine_; }
  const CaptureEngine& engine() const { return engine_; }

  DeviceTable<kDevices>& devices() { return devices_; }
  const DeviceTable<kDevices>& devices() const { return devices_; }

  Counters& counters() { return engine_.counters(); }

  // Set the filter from a spec string. On a bad specification the previous filter
  // stays in force and false is returned, because a sniffer that ended up filtering
  // nothing because of a typo looks exactly like a silent band.
  bool setFilter(const char* spec) { return engine_.setFilter(spec); }
  void setFilter(const FilterSpec& f) { engine_.setFilter(f); }
  FilterSpec& filter() { return engine_.filter(); }
  const FilterSpec& filter() const { return engine_.filter(); }
  MemoryReport& memory() { return memory_; }

  // Sinks. Fixed array: no allocation, and the count is checked rather than
  // discovered when the fourth client cannot connect.
  bool addSink(LineSink* sink) {
    if (sink == nullptr || sinkCount_ >= kMaxSinks) return false;
    sinks_[sinkCount_] = sink;
    ++sinkCount_;
    return true;
  }
  std::size_t sinkCount() const { return sinkCount_; }

  // The capture ring. Kept here rather than in the engine because the ring is
  // retention policy and the engine is analysis; a cleared counter set must not
  // clear the last twenty frames somebody has not read yet.
  RingLog<kRing>& ring() { return ring_; }
  const RingLog<kRing>& ring() const { return ring_; }

  // Take a freshly captured record: render, dispatch, remember the node.
  //
  // The device list is updated *before* the filter is consulted, deliberately. A
  // filter changes what is shown, not what was heard, and a device list that
  // emptied because somebody typed `filter proto=mt` would be actively misleading.
  ConsoleResult observe(const Record& r, std::uint32_t nowMs) {
    rememberDevice(r, nowMs);

    ConsoleResult res;
    res.ok = true;

    // Filtered records are counted but not emitted. The counter is the operator's
    // only way to tell "my filter is too narrow" from "the band went quiet".
    if (r.filtered) return res;

    const std::size_t n = toJsonLine(r, line_, sizeof(line_));
    if (n == 0) {
      res.ok = false;
      std::snprintf(res.error, sizeof(res.error), "capture line did not fit %u bytes",
                    static_cast<unsigned>(sizeof(line_)));
      return res;
    }

    if (!ring_.push(line_, n)) {
      // The ring declined it -- the line was too long -- but every sink still gets
      // it, so this is not a lost capture.
      res.ok = false;
      std::snprintf(res.error, sizeof(res.error), "line did not fit the %u-byte ring slot",
                    static_cast<unsigned>(kRingLineBytes));
    }

    for (std::size_t i = 0; i < sinkCount_; ++i) {
      const std::size_t cap = sinks_[i]->maxLine();
      if (cap < n) continue;  // this destination cannot hold it; the others still can
      if (!sinks_[i]->putLine(line_, n)) res.ok = false;
      ++res.linesOut;
    }
    return res;
  }

  // Execute one command line. The result says whether it worked; the output has
  // already gone to the sinks.
  ConsoleResult execute(const char* line) {
    ConsoleResult res;
    const ParseResult parsed = parseCommand(line);

    if (!parsed.ok) {
      res.ok = false;
      std::snprintf(res.error, sizeof(res.error), "%s", parsed.error);
      if (parsed.suggestion[0] != '\0') {
        emit(parsed.suggestion);
        ++res.linesOut;
      }
      return res;
    }

    if (parsed.command.id == CommandId::None) {
      res.ok = true;
      return res;
    }

    switch (parsed.command.id) {
      case CommandId::Help:
        emitAll(commandList());
        break;

      case CommandId::Stats:
        emitAll(renderCounters(counters()));
        break;

      case CommandId::Memory:
        emitAll(renderMemory(memory_));
        break;

      case CommandId::Plan:
        emitAll(planLine());
        break;

      case CommandId::Filter: {
        char error[96];
        FilterSpec spec;
        if (!parseFilter(parsed.command.arg, &spec, error, sizeof(error))) {
          res.ok = false;
          std::snprintf(res.error, sizeof(res.error), "%s", error);
          emit(describeFilter(engine_.filter()).c_str());
          ++res.linesOut;
          return res;
        }
        engine_.setFilter(spec);
        // Echoed unconditionally. A filter whose effect you cannot see is a filter
        // you will get wrong.
        emit(describeFilter(engine_.filter()).c_str());
        ++res.linesOut;
        break;
      }

      case CommandId::Devices:
        listDevices(parsed.command.order, lastNowMs_);
        break;

      case CommandId::Dump:
        replay();
        break;

      case CommandId::Hex:
      case CommandId::Text: {
        CaptureOptions o = engine_.options();
        const bool on = std::strcmp(parsed.command.arg, "off") != 0;
        if (std::strcmp(parsed.command.arg, "toggle") == 0) {
          o.includeBytes = !o.includeBytes;
          o.plainText = !o.plainText;
        } else if (parsed.command.id == CommandId::Hex) {
          o.includeBytes = on;
        } else {
          o.plainText = on;
        }
        engine_.setOptions(o);
        emit(renderOptions(o).c_str());
        ++res.linesOut;
        break;
      }

      case CommandId::Emitted:
        emit(emittedLine().c_str());
        ++res.linesOut;
        break;

      case CommandId::Reset:
        engine_.reset();
        devices_.clear();
        ring_.clear();
        emit("reset: counters, device list and ring cleared; the filter is unchanged");
        ++res.linesOut;
        break;

      case CommandId::Beacon:
      case CommandId::Arm:
      case CommandId::Disarm:
      case CommandId::Tail:
      case CommandId::Save:
      case CommandId::Load:
        // Handled by the caller, which owns the radio and the filesystem. The
        // console parses and renders; it does not transmit and it does not write.
        emit(renderCommand(parsed.command).c_str());
        ++res.linesOut;
        break;

      default:
        break;
    }

    res.ok = true;
    return res;
  }

  // The device list, rendered for a destination that can take long lines. A phone
  // gets this verbatim; the OLED renders its own subset from `devices()`.
  //
  // `nowMs` is the same clock the records were stamped with, so the "last seen"
  // column is in real units rather than an absolute timestamp nobody can read.
  std::string renderDeviceList(Order order, std::uint32_t nowMs) {
    Device scratch[kDevices];
    const std::size_t n = devices_.list(order, scratch, kDevices);
    if (n == 0) return "no nodes heard yet\n";

    std::string s;
    char buf[224];

    std::snprintf(buf, sizeof(buf), "%u nodes, %s order, %u direct, %u within 3 hops\n",
                  static_cast<unsigned>(n), orderName(order),
                  static_cast<unsigned>(devices_.direct()),
                  static_cast<unsigned>(devices_.withinHops(3)));
    s += buf;

    for (std::size_t i = 0; i < n; ++i) {
      const Device& d = scratch[i];

      char id[kDeviceIdBytes * 2 + 1];
      for (std::size_t k = 0; k < kDeviceIdBytes; ++k) {
        std::snprintf(id + (k * 2), 3, "%02x", static_cast<unsigned>(d.id[k]));
      }

      char hops[8];
      if (d.hopsValid) {
        std::snprintf(hops, sizeof(hops), "%u", static_cast<unsigned>(d.hops));
      } else {
        std::snprintf(hops, sizeof(hops), "?");
      }

      const std::uint32_t ago = (nowMs > d.lastSeenMs) ? (nowMs - d.lastSeenMs) : 0u;

      std::snprintf(buf, sizeof(buf), "%-2u %s %s hops=%s", static_cast<unsigned>(i),
                    protocolTag(d.protocol), id, hops);
      s += buf;

      if (d.bestRssiValid) {
        std::snprintf(buf, sizeof(buf), " rssi=%d", static_cast<int>(d.bestRssiDbm));
        s += buf;
      }
      if (d.role != static_cast<std::uint8_t>(NodeRole::Unknown)) {
        std::snprintf(buf, sizeof(buf), " role=%s", nodeRoleName(static_cast<NodeRole>(d.role)));
        s += buf;
      }
      if (d.hasName && d.name[0] != '\0') {
        std::snprintf(buf, sizeof(buf), " name=%s", d.name);
        s += buf;
      }
      std::snprintf(buf, sizeof(buf), " x%u %ums ago %s\n", static_cast<unsigned>(d.frames),
                    static_cast<unsigned>(ago), attributionName(d.attribution));
      s += buf;
    }
    return s;
  }

  // Remember the clock, so a `devices` command with no argument still reports "last
  // seen" in real units.
  void noteNow(std::uint32_t nowMs) { lastNowMs_ = nowMs; }

 private:
  static constexpr std::size_t kMaxSinks = 4;

  void emit(const char* text) {
    const std::size_t n = std::strlen(text);
    for (std::size_t i = 0; i < sinkCount_; ++i) {
      if (sinks_[i]->maxLine() < n) continue;
      sinks_[i]->putLine(text, n);
    }
  }

  void emitAll(const std::string& text) {
    std::size_t start = 0;
    while (start <= text.size()) {
      std::size_t end = text.find('\n', start);
      if (end == std::string::npos) end = text.size();
      emit(text.substr(start, end - start).c_str());
      if (end >= text.size()) break;
      start = end + 1;
    }
  }

  void listDevices(Order order, std::uint32_t nowMs) {
    emitAll(renderDeviceList(order, nowMs));
  }

  void replay() {
    char out[Command::kArgBytes];
    for (std::size_t i = 0; i < ring_.size(); ++i) {
      if (!ring_.get(i, out, sizeof(out))) continue;
      emit(out);
    }
    if (ring_.size() == 0) emit("the capture ring is empty");
  }

  // Move a record's identity into the device list. A record that names no node
  // contributes nothing: a GRP_TXT has a channel and a sender we cannot see, and
  // inventing an entry for the channel would put a phantom node in the list.
  void rememberDevice(const Record& r, std::uint32_t nowMs) {
    if (!r.hasIdentity) return;

    Device& d = devices_.observe(r.identityProtocol, identityFor(r), r.identity, nowMs);
    if (r.hopsValid && (!d.hopsValid || r.hops < d.hops)) {
      d.hops = r.hops;
      d.hopsValid = true;
    }
    if (r.link.rssiDbm > d.bestRssiDbm || !d.bestRssiValid) {
      d.bestRssiDbm = r.link.rssiDbm;
      d.bestRssiValid = true;
    }
    if (r.role != 0) d.role = r.role;
    if (r.hasName && r.name[0] != '\0' && d.name[0] == '\0') {
      std::size_t k = 0;
      for (; k + 1 < sizeof(d.name) && r.name[k] != '\0'; ++k) d.name[k] = r.name[k];
      d.name[k] = '\0';
      d.hasName = true;
    }
    if (r.hasText && r.text[0] != '\0') {
      std::size_t k = 0;
      for (; k + 1 < sizeof(d.lastText) && r.text[k] != '\0'; ++k) d.lastText[k] = r.text[k];
      d.lastText[k] = '\0';
      d.hasText = true;
    }
    if (d.attribution == Attribution::Unattributed &&
        r.provenance.attribution != Attribution::Unattributed) {
      d.attribution = r.provenance.attribution;
    }
  }

  static Identity identityFor(const Record& r) {
    switch (r.identityProtocol) {
      case Protocol::MeshCore:
        return Identity::MeshCoreKeyPrefix;
      case Protocol::Meshtastic:
        return Identity::MeshtasticNodeNum;
      case Protocol::LoRaWan:
        return Identity::LoRaWanDevAddr;
      default:
        return Identity::FingerprintOnly;
    }
  }

  std::string planLine() const {
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "listening  %s\n"
                  "mode       %s\n"
                  "slots      %u declared, %u fit this flash\n"
                  "filter     %s\n"
                  "devices    %u of %u\n"
                  "ring       %u of %u retained\n",
                  describeRf(lastPlan_).c_str(), txModeName(),
                  static_cast<unsigned>(memory_.slots), static_cast<unsigned>(memory_.capacity),
                  describeFilter(engine_.filter()).c_str(),
                  static_cast<unsigned>(devices_.size()), static_cast<unsigned>(kDevices),
                  static_cast<unsigned>(ring_.size()), static_cast<unsigned>(kRing));
    return buf;
  }

  std::string emittedLine() const {
    char buf[200];
    std::snprintf(buf, sizeof(buf), "tx mode: %s\nbeacons emitted this boot: %u\n%s\n",
                  txModeName(), static_cast<unsigned>(BeaconTx::emitted()),
                  mayEverTransmit() ? kBeaconStatement : kRxOnlyStatement);
    return buf;
  }

  static std::string renderOptions(const CaptureOptions& o) {
    char buf[160];
    std::snprintf(buf, sizeof(buf), "raw bytes in lines: %s\ndecoded message text: %s\n",
                  o.includeBytes ? "on" : "off", o.plainText ? "on" : "off");
    return buf;
  }

 public:
  void noteLastPlan(const RfParams& p) { lastPlan_ = p; }

  CaptureEngine engine_;
  DeviceTable<kDevices> devices_;
  RingLog<kRing> ring_;
  MemoryReport memory_;
  RfParams lastPlan_;

 private:
  LineSink* sinks_[kMaxSinks] = {};
  std::size_t sinkCount_ = 0;
  std::uint32_t lastNowMs_ = 0;
  char line_[kMaxJsonLineBytes] = {};
};

}  // namespace sniff
