// SPDX-License-Identifier: MIT
//
// Beacon -- building a message to send to repeaters, over several networks, several
// times. Encoding only.
//
// This is the half of the transmit feature that can be written without a radio,
// and it is where all of the interesting work is: what does a "send this to every
// repeater with maximum reach" actually mean on two different protocols?
//
// On **MeshCore** it is well defined. A GRP_TXT is a channel hash and some text,
// sent with a path length of zero and flooded; the number of hops it travels is set
// by the destination's max hops in its own configuration, not by the sender, so
// "maximum reach" from here means "let it flood" rather than "ask for 7 hops". The
// header is one byte and the payload is the channel, flags and text -- both
// documented, both plaintext, both encodable right here.
//
// On **Meshtastic** a text message is a `Data` protobuf whose payload is a
// portnum-tagged application message, all of which has to be varint-encoded by
// hand. It is more work than MeshCore and it is still deterministic, so it is here
// rather than deferred to the radio layer where it could not be tested.
//
// Three things are deliberately *not* in this file:
//
//   * **No keys, no encryption.** Encoding an encrypted Meshtastic payload needs
//     the channel PSK, and an encoder that takes a key is an encoder that gets a
//     key pasted at it. The beacon here sends plaintext on the primary channel
//     only, which is the same thing anybody does when they set a node up.
//
//   * **No airtime management.** Deciding *when* it is legal to transmit is a
//     region question with a real answer, and guessing at it from a sniffer that
//     may be tuned to the wrong band is how you earn an operator an angry letter.
//     `BeaconSchedule` holds the *timing* the sender asked for and the transmit
//     layer applies the region's duty cycle on top; the schedule never assumes it
//     is allowed to transmit.
//
//   * **No transmission.** `TxSink::send()` is an interface. On the device the only
//     implementation is in the radio layer, which is compiled out entirely unless
//     `SNIFFER_TX_CAPABLE=1`. On a laptop the implementation is a file. That is the
//     whole reason this module can be tested to exhaustion: nothing it builds can
//     reach an antenna from a test binary.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/MeshCoreFrame.hpp"
#include "sniffer/MeshtasticFrame.hpp"
#include "sniffer/Proto.hpp"
#include "sniffer/Protocol.hpp"

namespace sniff {

// Longest text a beacon carries. Bounded, because the text is typed by an operator
// over a serial console and the frame has to fit a LoRa packet at SF11 -- the
// MeshCore payload ceiling is 184 bytes and a GRP_TXT spends three of them on
// structure before the first character.
constexpr std::size_t kMaxBeaconText = 160;

// One message to put on the air, in one protocol's framing.
struct BeaconFrame {
  Protocol protocol = Protocol::Unknown;

  // The bytes to transmit. Inline and fixed, because a beacon is built once and
  // sent repeatedly and there is no reason for it to live on the heap.
  std::uint8_t data[meshtastic::kHeaderBytes + 240] = {};
  std::size_t length = 0;

  // What it is, for the log. A beacon that goes out is recorded in the capture
  // stream like anything else, so a capture file says "this device was not passive".
  char label[64] = {};
};

// Where a beacon goes. A channel hash on MeshCore, a channel hash on Meshtastic;
// one field because the two mean the same thing and keeping them separate would
// invite setting one and forgetting the other.
struct BeaconTarget {
  Protocol protocol = Protocol::Unknown;
  std::uint8_t channelHash = 0;
};

// How many times to send, and how long to wait between.
//
// Repeating is the point: a LoRa frame is delivered perhaps once in three, and a
// single beacon is not a beacon. `count` is capped and the interval has a floor,
// because an operator who types `count=200,interval=50` and gets 200 transmissions
// in ten seconds has built a denial-of-service tool and not a beacon.
struct BeaconSchedule {
  std::uint8_t count = 3;
  std::uint32_t intervalMs = 5000;
};

constexpr std::uint8_t kMaxBeaconRepeats = 32;
constexpr std::uint32_t kMinBeaconIntervalMs = 1500;

struct EncodeResult {
  bool ok = false;
  char reason[96] = {};
};

// A sink that accepts a beacon. The only interface between this module and a radio.
class TxSink {
 public:
  virtual ~TxSink() = default;

  // Return false to stop: the sink declines when the region's airtime budget says
  // no, and the schedule stops there rather than pretending it sent the rest.
  virtual bool send(const BeaconFrame& frame) = 0;
};

// ---------------------------------------------------------------------------
// MeshCore
// ---------------------------------------------------------------------------

// Build a GRP_TXT: header, zero-length path, channel hash, flags, text.
//
// header = (version << 6) | (payloadType << 2) | routeType
//       = (0 << 6) | (0x5 << 2) | 0x01        ->  0x15
//
// The path length byte is 0x00: no path, flooded. That is how a beacon reaches
// maximum reach -- the mesh does the work, and every repeater that hears it
// rebroadcasts.
BeaconFrame meshCoreGroupText(std::uint8_t channelHash, const char* text);

// ---------------------------------------------------------------------------
// Meshtastic
// ---------------------------------------------------------------------------

// Build a plaintext TEXT_MESSAGE_APP Data protobuf on the primary channel.
//
//   header(16) | Data{ from(1) fixed32, to(2) fixed32, channel(3)=0,
//                      payload(4) = { portnum(1)=1, text(1) string } }
//
// `from` is the sending node number, which is why the caller supplies it: this
// firmware is not a Meshtastic node and has no identity of its own on that mesh,
// so it uses the one the operator gave it. Documented here because a beacon
// claiming to be from node 0x00000000 would be a lie visible to the whole mesh.
BeaconFrame meshtasticText(std::uint32_t fromNode, std::uint32_t toNode, const char* text);

// ---------------------------------------------------------------------------
// Multi-network
// ---------------------------------------------------------------------------

// One beacon, many targets, many sends. `out` receives `targets * count` frames,
// which the caller sized. Returns the number built, or 0 with a reason.
//
// The ordering is deliberate: target-major, then repeat. Every network gets its
// first copy before any network gets its second, so a duty-cycle limit that stops
// the run halfway through still covers every network at least once. The other
// ordering would put five copies on one network and nothing on the other, which is
// the failure an operator would not notice until they wondered why nobody on the
// second mesh received anything.
struct BeaconPlan {
  std::size_t built = 0;
  std::size_t skipped = 0;
  char reason[96] = {};
};

BeaconPlan buildBeacon(const BeaconTarget* targets, std::size_t targetCount, const char* text,
                       const BeaconSchedule& schedule, BeaconFrame* out, std::size_t outMax);

// Clamp a schedule to what is legal for a device to do without thinking. Returns
// false and explains when the request was refused rather than silently reduced,
// because "I asked for 200 and got 32" is worse than being told why.
bool clampSchedule(BeaconSchedule* s);

// A human summary of a frame, for the log line the transmit layer prints.
std::string describeBeacon(const BeaconFrame& f);

}  // namespace sniff
