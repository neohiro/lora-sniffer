// SPDX-License-Identifier: MIT
//
// LoRaWanFrame -- the LoRaWAN PHY payload, which is plaintext by design.
//
// LoRaWAN puts its entire security model around the payload: the PHY header and
// the frame header are both in the clear, and only the FRMPayload is encrypted
// (or, for a join request, plaintext by necessity -- the device does not yet hold
// a key).
//
// That makes this the one protocol on this band where an unkeyed sniffer is not
// merely reading metadata. A JoinRequest carries a DevEUI, a DevNonce and an
// application nonce in the clear. For an operator surveying a frequency this is
// the most useful single thing a sniffer can surface: LoRaWAN deployments are
// easy to find and easy to describe precisely.
//
// Which is exactly why it belongs in a tool that also refuses to guess. LoRaWAN
// is not MeshCore or Meshtastic and its frames do not belong on a community mesh
// frequency; a LoRaWAN frame arriving on 869.525 is somebody's infrastructure,
// and the honest report is "this is a LoRaWAN uplink from a device whose DevEUI
// is X", not "this is a node on your mesh".
//
// Layout, per the LoRaWAN specification's PHY payload:
//
//   byte 0      MHDR      MType (2b) | Major (2b)
//   byte 1..2   MACHDR    MType (2b) | Major (2b) | Minor (2b)
//   byte 3..6   FHDR      DevAddr (4B, little-endian) | FCtrl (1B) | FCnt (2B LE)
//   byte 7      FPort/FOptsLen
//   ..          FOpts | FRMPayload
//   last 4      MIC
//
// For MType 0 (JoinRequest) the MACHDR/FHDR/FPort layout does not apply and the
// body is parsed as the join-request message instead, which is why this decoder
// branches on MType before it reads anything else.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/Protocol.hpp"
#include "sniffer/Provenance.hpp"

namespace sniff {
namespace lorawan {

enum class MType : std::uint8_t {
  JoinRequest = 0,
  JoinAccept = 1,
  UnconfirmedDataUp = 2,
  UnconfirmedDataDown = 3,
  ConfirmedDataUp = 4,
  ConfirmedDataDown = 5,
  RejoinRequest = 6,
  Propagate = 7,
};

const char* mTypeName(MType t);

// Class A, B or C. Derived from the two low FCtrl bits, which is why it is
// reported alongside rather than guessed at later.
enum class Class : std::uint8_t { A = 0, B = 1, C = 2 };

const char* className(Class c);

struct Frame {
  MType mType = MType::UnconfirmedDataUp;
  bool majorValid = false;
  std::uint8_t major = 0;
  std::uint8_t minor = 0;

  // Data frames only.
  std::uint32_t devAddr = 0;
  std::uint8_t fCtrl = 0;
  bool adr = false;
  bool adrAckReq = false;
  bool ack = false;
  bool classB = false;
  Class downlinkClass = Class::A;
  std::uint16_t fCnt = 0;
  std::uint8_t fPort = 0;
  std::size_t payloadOffset = 0;
  std::size_t payloadLength = 0;

  // JoinRequest only, and the reason this decoder is worth having.
  std::uint64_t devEui = 0;
  std::uint64_t appEui = 0;
  std::uint16_t devNonce = 0;

  std::size_t micOffset = 0;
  std::size_t micLength = 0;

  bool wellFormed = false;
  Reason problem = Reason::FullyDecoded;
  Provenance provenance;
};

Frame parse(const std::uint8_t* data, std::size_t length);

// One-line summary.
std::string describe(const Frame& f);

}  // namespace lorawan
}  // namespace sniff
