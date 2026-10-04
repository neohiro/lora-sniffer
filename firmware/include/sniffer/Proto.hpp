// SPDX-License-Identifier: MIT
//
// Proto -- just enough protobuf wire format to read a Meshtastic `Data`.
//
// Not a protobuf library, and deliberately not a general one. Two facts make a
// general implementation the wrong choice here:
//
//   1. On a sniffer the schema is often *not available*. A frame on a channel
//      nobody here holds a key for is opaque by design. What is wanted is the
//      ability to walk the wire format and pull out the few fields whose numbers
//      are public and stable -- `from`, `to`, `channel`, `payload` -- and then
//      say honestly that the rest is a length-delimited blob of unknown
//      structure.
//
//   2. The alternative, vendoring nanopb or protobuf-c, would put a code
//      generator and a runtime between this firmware and a capture format whose
//      whole value is that you can read it with `cat`. The capture stream is a
//      line of JSON and the parser for it is four lines of Python. A sniffer
//      that cannot be read with `cat` is not a sniffer anybody will run on a
//      rooftop.
//
// So this walks tags and skips values it does not care about, and it refuses --
// loudly, with a Reason -- on anything malformed. A truncated or over-long
// varint is a corrupt capture, and returning a plausible-looking field value out
// of one is how a sniffer ends up confidently wrong.

#pragma once

#include <cstddef>
#include <cstdint>

namespace sniff {
namespace proto {

enum class WireType : std::uint8_t {
  Varint = 0,
  Fixed64 = 1,
  LengthDelimited = 2,
  StartGroup = 3,  // deprecated in proto3; never valid here
  Fixed32 = 5,
};

// One tag as read off the wire.
struct Tag {
  std::uint32_t field = 0;
  WireType wire = WireType::Varint;
};

// A cursor over a buffer. Every read is bounds-checked; there is no unchecked
// path, because the input is by definition hostile.
class Reader {
 public:
  Reader(const std::uint8_t* data, std::size_t length)
      : data_(data), length_(length) {}

  bool done() const { return offset_ >= length_; }
  std::size_t offset() const { return offset_; }
  std::size_t remaining() const { return offset_ >= length_ ? 0 : length_ - offset_; }

  // Read a tag. Fails on a truncated varint, on field number 0 (illegal) and on
  // a group marker (deprecated, and nothing legitimate emits one).
  bool next(Tag* out) {
    if (out == nullptr) return false;
    std::uint64_t key = 0;
    if (!varint(&key)) return false;
    const std::uint32_t wireBits = static_cast<std::uint32_t>(key & 0x07u);
    if (wireBits == 3 || wireBits == 4) return false;
    const std::uint32_t field = static_cast<std::uint32_t>(key >> 3);
    if (field == 0) return false;
    out->field = field;
    out->wire = static_cast<WireType>(wireBits);
    return true;
  }

  bool varint(std::uint64_t* out) {
    if (out == nullptr) return false;
    std::uint64_t v = 0;
    std::uint8_t shift = 0;
    for (std::size_t i = 0; i < 10; ++i) {
      if (offset_ >= length_) return false;
      const std::uint8_t b = data_[offset_];
      ++offset_;
      v |= static_cast<std::uint64_t>(b & 0x7Fu) << shift;
      if ((b & 0x80u) == 0) {
        *out = v;
        return true;
      }
      shift = static_cast<std::uint8_t>(shift + 7);
      // Ten bytes is the proto3 maximum; a tenth byte may only carry the
      // remaining four bits. Anything longer is a corrupt or hostile buffer and
      // looping further would let it spin.
      if (shift > 63) return false;
    }
    return false;
  }

  bool fixed32(std::uint32_t* out) {
    if (out == nullptr) return false;
    if (offset_ + 4 > length_) return false;
    *out = static_cast<std::uint32_t>(data_[offset_]) |
           (static_cast<std::uint32_t>(data_[offset_ + 1]) << 8) |
           (static_cast<std::uint32_t>(data_[offset_ + 2]) << 16) |
           (static_cast<std::uint32_t>(data_[offset_ + 3]) << 24);
    offset_ += 4;
    return true;
  }

  bool fixed64(std::uint64_t* out) {
    if (out == nullptr) return false;
    if (offset_ + 8 > length_) return false;
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
      v |= static_cast<std::uint64_t>(data_[offset_ + i]) << (8 * i);
    }
    offset_ += 8;
    *out = v;
    return true;
  }

  // Length-delimited: the length prefix plus the payload extent. The returned
  // pointer aliases the caller's buffer; nothing is copied.
  bool bytes(const std::uint8_t** out, std::size_t* outLen) {
    if (out == nullptr || outLen == nullptr) return false;
    std::uint64_t n = 0;
    if (!varint(&n)) return false;
    if (n > remaining()) return false;
    *out = data_ + offset_;
    *outLen = static_cast<std::size_t>(n);
    offset_ += static_cast<std::size_t>(n);
    return true;
  }

  // Advance past a field whose value we do not want, whatever its type.
  bool skip(WireType wire) {
    switch (wire) {
      case WireType::Varint: {
        std::uint64_t v = 0;
        return varint(&v);
      }
      case WireType::Fixed64: {
        std::uint64_t v = 0;
        return fixed64(&v);
      }
      case WireType::Fixed32: {
        std::uint32_t v = 0;
        return fixed32(&v);
      }
      case WireType::LengthDelimited: {
        const std::uint8_t* p = nullptr;
        std::size_t n = 0;
        return bytes(&p, &n);
      }
      case WireType::StartGroup:
      default:
        return false;
    }
  }

  // A sub-reader over a nested message, for one level of recursion only.
  static Reader sub(const std::uint8_t* data, std::size_t length) {
    return Reader(data, length);
  }

 private:
  const std::uint8_t* data_;
  std::size_t length_;
  std::size_t offset_ = 0;
};

}  // namespace proto
}  // namespace sniff
