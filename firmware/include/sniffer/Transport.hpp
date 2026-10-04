// SPDX-License-Identifier: MIT
//
// Transport -- one capture stream, four destinations, one interface.
//
// USB serial, BLE and WiFi are interchangeable labels on the same service, which
// is the rule the provisioning state machine in the bridge established and the
// rule that makes a sniffer usable from a phone, a laptop and a serial console
// without three code paths. This file is where that rule is implemented, and it is
// portable so it can be tested on a laptop with three fake transports and no
// hardware.
//
// The interesting problem is not the interface, it is what happens when one
// destination is slow. A phone on BLE with nobody connected, a laptop whose socket
// buffer is full, a serial port at 115200 baud: all three block or drop, and a
// capture that blocks on any of them stops capturing -- which defeats the point of
// a device whose job is to notice what is on the air.
//
// So every sink has a budget and the fan-out **never blocks**. A sink that cannot
// take a record says so, and the record is dropped *for that sink only* and
// counted. Losing one record to a stalled BLE link is a hole in the phone's copy;
// stalling the radio because the phone went out of range is losing the capture.
//
// The ring log is the fourth destination and the odd one out: it is the only sink
// that has to be bounded in a way that persists, because it lives in the same flash
// as the mesh firmware's settings. It is text, not `Record` objects -- a `Record`
// is 1928 bytes and a JSON line is a few hundred, which is the difference
// between a hundred retained lines and six.

#pragma once

#include <cstddef>
#include <cstdint>

#include "sniffer/Record.hpp"

namespace sniff {

// One line of retained capture. The number is a policy choice driven by memory, not
// by taste -- see MemoryBudget.hpp -- and `ringCapacity` on the profile is what
// sets it.
constexpr std::size_t kRingLineBytes = 320;

// Where a record went, and where it did not. Returned by every publish so the
// caller can log it rather than guess.
struct DispatchReport {
  std::uint8_t delivered = 0;
  std::uint8_t dropped = 0;

  bool ok() const { return dropped == 0; }
};

// A destination for capture records. Three methods because three different things
// are useful from different transports: bytes for a serial or socket, a record for
// one that wants to re-serialise it itself, and a status line for a screen.
class CaptureSink {
 public:
  virtual ~CaptureSink() = default;

  virtual const char* name() const = 0;

  // Return false to decline. A declining sink is not an error; it is a sink that
  // has no room right now, and the fan-out records that fact.
  virtual bool putLine(const char* line, std::size_t length) = 0;

  // Optional: a sink that can do better than a line takes the record. The default
  // implementation declines, so a new transport only has to implement one method.
  virtual bool putRecord(const Record& r) {
    (void)r;
    return false;
  }

  // Optional: a sink that can render its own status -- an OLED, or the WebSocket
  // console a phone connects to.
  virtual bool putStatus(const char* text) {
    (void)text;
    return false;
  }

  // Frames this sink refused since boot. The number an operator checks before
  // concluding that a phone app has a bug.
  std::uint32_t dropped() const { return dropped_; }
  void noteDropped() { ++dropped_; }
  void resetDropped() { dropped_ = 0; }

 private:
  std::uint32_t dropped_ = 0;
};

// ---------------------------------------------------------------------------
// Fan-out
// ---------------------------------------------------------------------------

// Publish to several sinks without blocking any of them. Fixed capacity, so the
// fan-out itself costs one pointer array and no allocation.
class Dispatcher {
 public:
  static constexpr std::size_t kMaxSinks = 5;

  void clear() {
    for (std::size_t i = 0; i < kMaxSinks; ++i) sinks_[i] = nullptr;
    count_ = 0;
  }

  // Adding a fourth destination when five are already in use is refused, not
  // silently dropped: a transport that never receives a record is the kind of thing
  // that is discovered a week later.
  bool add(CaptureSink* sink) {
    if (sink == nullptr || count_ >= kMaxSinks) return false;
    sinks_[count_] = sink;
    ++count_;
    return true;
  }

  std::size_t size() const { return count_; }
  CaptureSink* at(std::size_t i) const { return i < count_ ? sinks_[i] : nullptr; }

  // Render once, deliver to everyone. Rendering per sink would mean N serialisations
  // of the same record, and on a microcontroller that is measurable.
  DispatchReport publishLine(const char* line, std::size_t length) {
    DispatchReport rep;
    for (std::size_t i = 0; i < count_; ++i) {
      if (sinks_[i]->putLine(line, length)) {
        ++rep.delivered;
      } else {
        ++rep.dropped;
        sinks_[i]->noteDropped();
      }
    }
    return rep;
  }

  // Offer the record to sinks that want it. A sink that declines falls back to the
  // line, which is why this takes both.
  DispatchReport publish(const Record& r, const char* line, std::size_t length) {
    DispatchReport rep;
    for (std::size_t i = 0; i < count_; ++i) {
      bool ok = sinks_[i]->putRecord(r);
      if (!ok) ok = sinks_[i]->putLine(line, length);
      if (ok) {
        ++rep.delivered;
      } else {
        ++rep.dropped;
        sinks_[i]->noteDropped();
      }
    }
    return rep;
  }

  DispatchReport publishStatus(const char* text) {
    DispatchReport rep;
    for (std::size_t i = 0; i < count_; ++i) {
      if (sinks_[i]->putStatus(text)) ++rep.delivered;
    }
    return rep;
  }

  std::uint32_t totalDropped() const {
    std::uint32_t n = 0;
    for (std::size_t i = 0; i < count_; ++i) n += sinks_[i]->dropped();
    return n;
  }

  void resetDropped() {
    for (std::size_t i = 0; i < count_; ++i) sinks_[i]->resetDropped();
  }

 private:
  CaptureSink* sinks_[kMaxSinks] = {};
  std::size_t count_ = 0;
};

// ---------------------------------------------------------------------------
// The ring log
// ---------------------------------------------------------------------------

// A fixed-capacity ring of the most recent lines, for replay after a reconnect and
// for `dump` on the serial console.
//
// Newest-wins rather than oldest-dropped, which is the opposite of a file: the
// value of a capture ring is the last thing that happened, and a rooftop device
// nobody has read from in a week should be holding this morning's frames.
template <std::size_t kCapacity>
class RingLog {
 public:
  static_assert(kCapacity > 0, "a ring log with no capacity is a bug");

  void clear() {
    head_ = 0;
    size_ = 0;
    total_ = 0;
    for (std::size_t i = 0; i < kCapacity; ++i) lengths_[i] = 0;
  }

  // Append, overwriting the oldest line when full. Returns false if the line does
  // not fit even in an empty slot -- refusing is better than storing half a JSON
  // object.
  bool push(const char* line, std::size_t length) {
    // The bound is what makes the narrowing cast below safe: a line that does not
    // fit an empty slot is refused rather than stored truncated, because half a JSON
    // object replays as a parse error rather than as a frame.
    if (length >= kRingLineBytes || length > 0xFFFFu) return false;

    std::size_t i = 0;
    while (i < length) {
      buf_[i] = line[i];
      ++i;
    }
    buf_[length] = '\0';
    lengths_[head_] = static_cast<std::uint16_t>(length);
    head_ = (head_ + 1) % kCapacity;
    if (size_ < kCapacity) ++size_;
    ++total_;
    return true;
  }

  // Copy out the k'th oldest retained line, for `dump`.
  bool get(std::size_t k, char* out, std::size_t cap) const {
    if (k >= size_ || cap == 0) return false;
    // Oldest retained is head_ - size_ (mod capacity).
    const std::size_t idx = ((head_ + kCapacity - size_) % kCapacity + k) % kCapacity;
    const std::size_t n = lengths_[idx];
    if (n + 1 > cap) return false;
    for (std::size_t i = 0; i < n; ++i) out[i] = buf_[idx * kRingLineBytes + i];
    out[n] = '\0';
    return true;
  }

  std::size_t size() const { return size_; }
  std::size_t capacity() const { return kCapacity; }

  // Total ever pushed, which is larger than size() once the ring has wrapped. The
  // difference is how much was overwritten, and reporting it is how an operator
  // finds out the ring is too small for the traffic they are getting.
  std::uint32_t total() const { return total_; }
  std::uint32_t overwritten() const {
    return (total_ > static_cast<std::uint32_t>(kCapacity))
               ? total_ - static_cast<std::uint32_t>(kCapacity)
               : 0u;
  }

 private:
  char buf_[kCapacity * kRingLineBytes] = {};
  std::uint16_t lengths_[kCapacity] = {};
  std::size_t head_ = 0;
  std::size_t size_ = 0;
  std::uint32_t total_ = 0;
};

// A ring log that can be handed to the Dispatcher, so a firmware image with one
// destination configured still exercises the same code path.
template <std::size_t kCapacity>
class RingSink : public CaptureSink {
 public:
  const char* name() const override { return "ring"; }

  bool putLine(const char* line, std::size_t length) override {
    if (!ring_.push(line, length)) {
      // Too long to retain. Not a drop of the record -- it went to the other sinks
      // -- but it is a drop of this sink's copy, and it is counted as one.
      noteDropped();
      return false;
    }
    return true;
  }

  RingLog<kCapacity>& ring() { return ring_; }
  const RingLog<kCapacity>& ring() const { return ring_; }

 private:
  RingLog<kCapacity> ring_;
};

}  // namespace sniff
