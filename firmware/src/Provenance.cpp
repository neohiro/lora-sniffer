// SPDX-License-Identifier: MIT

#include "sniffer/Provenance.hpp"

namespace sniff {

const char* decoderIdName(DecoderId id) {
  switch (id) {
    case DecoderId::MeshCoreV1:
      return "meshcore.v1";
    case DecoderId::MeshCoreAdvert:
      return "meshcore.advert";
    case DecoderId::MeshCoreGroupText:
      return "meshcore.grp_txt";
    case DecoderId::MeshCoreControl:
      return "meshcore.control";
    case DecoderId::MeshtasticHeader:
      return "meshtastic.meshheader";
    case DecoderId::MeshtasticData:
      return "meshtastic.data";
    case DecoderId::LoRaWanPhy:
      return "lorawan.phy";
    case DecoderId::ReticulumRNode:
      return "reticulum.rnode";
    case DecoderId::None:
    default:
      return "none";
  }
}

DecoderId owningDecoder(Protocol protocol) {
  switch (protocol) {
    case Protocol::MeshCore:
      return DecoderId::MeshCoreV1;
    case Protocol::Meshtastic:
      return DecoderId::MeshtasticHeader;
    case Protocol::LoRaWan:
      return DecoderId::LoRaWanPhy;
    case Protocol::Reticulum:
      // Deliberately honest rather than aspirational. The sync word is known
      // and documented; the RNode frame header is not vendored here. Claiming a
      // decoder that does not exist would put a name in the capture stream that
      // resolves to nothing, which is worse than saying "none".
      return DecoderId::None;
    case Protocol::Custom:
    case Protocol::Unknown:
    default:
      return DecoderId::None;
  }
}

const char* attributionName(Attribution a) {
  switch (a) {
    case Attribution::Attributed:
      return "attributed";
    case Attribution::Partial:
      return "partial";
    case Attribution::Unattributed:
    default:
      return "unattributed";
    }
}

const char* reasonName(Reason r) {
  switch (r) {
    case Reason::FullyDecoded:
      return "fully-decoded";
    case Reason::EncryptedNoKey:
      return "encrypted-no-key";
    case Reason::MeshCoreEncrypted:
      return "meshcore-encrypted";
    case Reason::Truncated:
      return "truncated";
    case Reason::ReservedValue:
      return "reserved-value";
    case Reason::CorruptOnAir:
      return "corrupt-on-air";
    case Reason::KnownSyncUnknownBody:
      return "known-sync-unknown-body";
    case Reason::ForeignSyncWord:
      return "foreign-sync-word";
    case Reason::NoEvidenceAtAll:
      return "no-evidence-at-all";
    case Reason::AnonymousButStructured:
      return "anonymous-but-structured";
    case Reason::NoiseOrTooShort:
    default:
      return "noise-or-too-short";
  }
}

const char* reasonDetail(Reason r) {
  switch (r) {
    case Reason::FullyDecoded:
      return "a registered decoder parsed this and produced named fields";

    case Reason::EncryptedNoKey:
      return "Meshtastic MeshHeader read; payload is AES-CCM ciphertext and this "
             "sniffer holds no key for that channel";

    case Reason::MeshCoreEncrypted:
      return "MeshCore v1 header read; payload is encrypted and this sniffer "
             "holds no key for that channel";

    case Reason::Truncated:
      return "the frame ended before the structure it declares was complete";

    case Reason::ReservedValue:
      return "the structure parsed but held a value the specification reserves, "
             "so the field cannot be named";

    case Reason::CorruptOnAir:
      return "the radio reported a CRC failure, so these bytes are not the "
             "bytes that were sent";

    case Reason::KnownSyncUnknownBody:
      return "the sync word belongs to a protocol this firmware names, but no "
             "decoder recognised the body -- a private or diverged channel, or a "
             "protocol nobody has written a decoder for yet";

    case Reason::ForeignSyncWord:
      return "a sync word no row in the registry has. On a shared band this is "
             "most likely another community, which is a finding, not a fault";

    case Reason::NoEvidenceAtAll:
      return "no sync byte was available and nothing in the bytes was "
             "conclusive. This is the honest answer, and it is the reason "
             "promiscuous capture is not optional";

    case Reason::AnonymousButStructured:
      return "no sync byte, but the body has enough internal structure to be a "
             "protocol rather than noise. Worth reading by hand";

    case Reason::NoiseOrTooShort:
    default:
      return "too short, or below the noise floor, to say anything about it";
  }
}

bool isUntraceable(Reason r) {
  // The bucket the brief asks to be easy to find: nothing in this firmware
  // could put a name to the frame. Deliberately narrow -- a frame that was
  // recognised and then found encrypted is *traceable*, it simply could not be
  // read, and lumping the two together would bury the interesting half.
  switch (r) {
    case Reason::ForeignSyncWord:
    case Reason::KnownSyncUnknownBody:
    case Reason::NoEvidenceAtAll:
    case Reason::AnonymousButStructured:
    case Reason::NoiseOrTooShort:
      return true;
    case Reason::FullyDecoded:
    case Reason::EncryptedNoKey:
    case Reason::MeshCoreEncrypted:
    case Reason::Truncated:
    case Reason::ReservedValue:
    case Reason::CorruptOnAir:
    default:
      return false;
  }
}

bool isAnomaly(Reason r) {
  // Reasons that mean "something on the air is not following the documented
  // format", as opposed to "correctly encrypted" or "correctly ignored".
  switch (r) {
    case Reason::Truncated:
    case Reason::ReservedValue:
    case Reason::CorruptOnAir:
    case Reason::KnownSyncUnknownBody:
      return true;
    case Reason::FullyDecoded:
    case Reason::EncryptedNoKey:
    case Reason::MeshCoreEncrypted:
    case Reason::ForeignSyncWord:
    case Reason::NoEvidenceAtAll:
    case Reason::AnonymousButStructured:
    case Reason::NoiseOrTooShort:
    default:
      return false;
  }
}

Provenance attribute(DecoderId decoder, Reason reason) {
  Provenance p;
  p.decoder = decoder;
  p.reason = reason;

  if (reason == Reason::FullyDecoded && decoder != DecoderId::None) {
    p.attribution = Attribution::Attributed;
    p.claimants = 1;
    return p;
  }

  if (isUntraceable(reason) || decoder == DecoderId::None) {
    p.attribution = Attribution::Unattributed;
    return p;
  }

  // A decoder claimed the frame but could not read past a point: the protocol is
  // known and the content is not.
  p.attribution = Attribution::Partial;
  p.claimants = 1;
  return p;
}

}  // namespace sniff
