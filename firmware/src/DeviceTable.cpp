// SPDX-License-Identifier: MIT

#include "sniffer/DeviceTable.hpp"

namespace sniff {

const char* identityName(Identity i) {
  switch (i) {
    case Identity::MeshCoreKeyPrefix:
      return "meshcore-key";
    case Identity::MeshtasticNodeNum:
      return "meshtastic-node";
    case Identity::LoRaWanDevEui:
      return "lorawan-deveui";
    case Identity::LoRaWanDevAddr:
      return "lorawan-devaddr";
    case Identity::FingerprintOnly:
    default:
      return "opaque";
  }
}

const char* nodeRoleName(NodeRole r) {
  switch (r) {
    case NodeRole::Chat:
      return "chat";
    case NodeRole::Repeater:
      return "repeater";
    case NodeRole::RoomServer:
      return "room_server";
    case NodeRole::Sensor:
      return "sensor";
    case NodeRole::Companion:
      return "companion";
    case NodeRole::Gateway:
      return "gateway";
    case NodeRole::Unknown:
    default:
      return "unknown";
  }
}

const char* orderName(Order o) {
  switch (o) {
    case Order::LastSeen:
      return "last-seen";
    case Order::MostFrames:
      return "most-frames";
    case Order::ShortestPath:
    default:
      return "shortest-path";
  }
}

}  // namespace sniff
