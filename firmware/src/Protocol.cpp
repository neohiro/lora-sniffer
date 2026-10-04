// SPDX-License-Identifier: MIT

#include "sniffer/Protocol.hpp"

#include <cstddef>

namespace sniff {
namespace {

struct SyncEntry {
  std::uint8_t sync;
  Protocol protocol;
};

// The reserved protocol table. Adding a framework is a row here, one
// enumerator in Protocol.hpp and one decoder in Provenance.cpp.
constexpr SyncEntry kSyncTable[] = {
    {kMeshCoreSync, Protocol::MeshCore},
    {kMeshtasticPublicSync, Protocol::Meshtastic},
    {kReticulumSync, Protocol::Reticulum},
    {kLoRaWanPublicSync, Protocol::LoRaWan},
};

constexpr std::size_t kSyncTableSize = sizeof(kSyncTable) / sizeof(kSyncTable[0]);

// ASCII case folding without <cctype>, so this behaves identically on a host
// toolchain and on the ESP32 and never depends on the active locale.
char lowerAscii(char c) {
  return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool equalsIgnoreCase(const char* a, const char* b) {
  if (a == nullptr || b == nullptr) return false;
  std::size_t i = 0;
  while (a[i] != '\0' && b[i] != '\0') {
    if (lowerAscii(a[i]) != lowerAscii(b[i])) return false;
    ++i;
  }
  return a[i] == '\0' && b[i] == '\0';
}

}  // namespace

const char* protocolTag(Protocol p) {
  switch (p) {
    case Protocol::MeshCore:
      return "MC";
    case Protocol::Meshtastic:
      return "MT";
    case Protocol::Reticulum:
      return "RT";
    case Protocol::LoRaWan:
      return "LW";
    case Protocol::Custom:
      return "CX";
    case Protocol::Unknown:
    default:
      return "??";
  }
}

const char* protocolName(Protocol p) {
  switch (p) {
    case Protocol::MeshCore:
      return "MeshCore";
    case Protocol::Meshtastic:
      return "Meshtastic";
    case Protocol::Reticulum:
      return "Reticulum";
    case Protocol::LoRaWan:
      return "LoRaWAN";
    case Protocol::Custom:
      return "Custom";
    case Protocol::Unknown:
    default:
      return "Unknown";
  }
}

bool parseProtocol(const char* text, Protocol* out) {
  if (text == nullptr || out == nullptr || text[0] == '\0') return false;

  for (std::uint8_t i = 0; i <= static_cast<std::uint8_t>(Protocol::Custom); ++i) {
    const Protocol candidate = static_cast<Protocol>(i);
    if (equalsIgnoreCase(text, protocolName(candidate)) ||
        equalsIgnoreCase(text, protocolTag(candidate))) {
      *out = candidate;
      return true;
    }
  }
  return false;
}

Protocol fromSyncWord(std::uint8_t syncWord) {
  // The wildcard carries no information. A wildcard that decided anything would
  // be a guess wearing a uniform.
  if (syncWord == 0x00) return Protocol::Unknown;
  for (std::size_t i = 0; i < kSyncTableSize; ++i) {
    if (kSyncTable[i].sync == syncWord) return kSyncTable[i].protocol;
  }
  return Protocol::Unknown;
}

}  // namespace sniff
