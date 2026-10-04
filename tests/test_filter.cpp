// SPDX-License-Identifier: MIT

#include <cstring>
#include <string>

#include "harness.hpp"
#include "sniffer/Filter.hpp"

using namespace sniff;

namespace {

// A record with just enough filled in for a filter to have something to work on.
Record makeRecord(Protocol proto, Attribution attrib, Reason reason, std::int16_t rssi,
                  std::uint32_t repeat, Network net) {
  Record r;
  r.protocol = proto;
  r.provenance = attribute(DecoderId::MeshCoreV1, reason);
  r.provenance.attribution = attrib;
  r.link.rssiDbm = rssi;
  r.repeatCount = repeat;
  r.verdict.network = net;
  r.decoded.add("proto", protocolTag(proto));
  r.decoded.add("text", "the quick brown fox");
  return r;
}

bool parse(const char* spec, FilterSpec* out) {
  char error[96];
  return parseFilter(spec, out, error, sizeof(error));
}

bool rejects(const char* spec) {
  FilterSpec f;
  char error[96];
  const bool ok = parseFilter(spec, &f, error, sizeof(error));
  CHECK_MSG(!ok, spec);
  CHECK_MSG(error[0] != '\0', "a rejected spec must say why");
  return !ok;
}

}  // namespace

void suite_filter() {
  harness::suite("Filter");

  // --- the default is "show me everything" ---------------------------------
  //
  // The most important property in this file. A filter that silently narrows
  // because a field was left unset is indistinguishable from a quiet band.

  {
    FilterSpec f;
    CHECK(!f.enabled);
    CHECK(!f.onlyUntraceable);
    CHECK(!f.onlyAnomalies);
    CHECK_MSG(f.includeCorrupt, "corrupt frames are shown by default");
    CHECK_MSG(!f.includeNoise, "noise is not, because it is not information");

    const Record r = makeRecord(Protocol::Unknown, Attribution::Unattributed,
                                Reason::ForeignSyncWord, -120, 1, Network::Unlisted);
    CHECK_MSG(filterMatches(f, r), "an unset filter passes a record that every rule would reject");
    CHECK(describeFilter(f) == "filter: off (everything shown)");
  }
  {
    CHECK(parse("", nullptr) == false);
    CHECK_MSG(!parse("anything", nullptr), "no destination is an error, not a crash");
  }
  {
    FilterSpec f;
    CHECK(parse("", &f));
    CHECK_MSG(!f.enabled, "an empty spec is the pass-everything filter");
  }

  // --- untraceable: the filter the brief asks for --------------------------

  {
    FilterSpec f;
    REQUIRE(parse("untraceable=true", &f));
    CHECK(f.onlyUntraceable);

    CHECK(filterMatches(f, makeRecord(Protocol::Unknown, Attribution::Unattributed,
                                     Reason::ForeignSyncWord, -100, 1, Network::Unlisted)));
    CHECK(filterMatches(f, makeRecord(Protocol::Unknown, Attribution::Unattributed,
                                     Reason::NoEvidenceAtAll, -100, 1, Network::Unknown)));
    CHECK_MSG(!filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                           Reason::FullyDecoded, -100, 1,
                                           Network::MeshCoreEu868)),
              "a decoded frame is traceable and must not appear under --only-unknown");
    CHECK_MSG(!filterMatches(f, makeRecord(Protocol::Meshtastic, Attribution::Partial,
                                           Reason::EncryptedNoKey, -100, 1,
                                           Network::MeshtasticEu868LongFast)),
              "nor does a frame whose key we lack: that one was traced to its protocol");
  }
  {
    FilterSpec f;
    REQUIRE(parse("untraceable", &f));
    CHECK(f.onlyUntraceable);
    FilterSpec g;
    REQUIRE(parse("untraceable=false", &g));
    CHECK(!g.onlyUntraceable);
  }

  // --- protocol ------------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("proto=mc", &f));
    CHECK(f.anyProtocol);
    CHECK(f.protocol[static_cast<std::size_t>(Protocol::MeshCore)]);
    CHECK(!f.protocol[static_cast<std::size_t>(Protocol::Meshtastic)]);

    CHECK(filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                     Reason::FullyDecoded, -100, 1, Network::MeshCoreEu868)));
    CHECK(!filterMatches(f, makeRecord(Protocol::Meshtastic, Attribution::Attributed,
                                      Reason::FullyDecoded, -100, 1,
                                      Network::MeshtasticEu868LongFast)));

    CHECK_MSG(rejects("proto=nonsense"), "an unknown protocol is refused, not ignored");
    CHECK_MSG(rejects("proto="), "proto with no value is refused");
  }
  {
    FilterSpec f;
    REQUIRE(parse("proto=meshcore,meshtastic", &f));
    CHECK(f.protocol[static_cast<std::size_t>(Protocol::MeshCore)]);
    CHECK(f.protocol[static_cast<std::size_t>(Protocol::Meshtastic)]);
    CHECK(filterMatches(f, makeRecord(Protocol::Meshtastic, Attribution::Attributed,
                                     Reason::FullyDecoded, -100, 1, Network::Unknown)));
  }

  // --- network -------------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("net=meshtastic", &f));
    CHECK(f.anyNetwork);
    CHECK_MSG(filterMatches(f, makeRecord(Protocol::Meshtastic, Attribution::Attributed,
                                         Reason::FullyDecoded, -100, 1,
                                         Network::MeshtasticEu868LongFast)),
              "matched on the network, not the protocol");
    CHECK(!filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                      Reason::FullyDecoded, -100, 1, Network::MeshCoreEu868)));
    CHECK(rejects("net=hamradio"));
  }

  // --- attribution ---------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("attrib=unattributed", &f));
    CHECK(f.anyAttribution);
    CHECK(filterMatches(f, makeRecord(Protocol::Unknown, Attribution::Unattributed,
                                     Reason::ForeignSyncWord, -100, 1, Network::Unlisted)));
    CHECK(!filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Partial,
                                      Reason::MeshCoreEncrypted, -100, 1,
                                      Network::MeshCoreEu868)));
    CHECK(rejects("attrib=maybe"));
    CHECK(rejects("attrib="));
  }
  {
    FilterSpec f;
    REQUIRE(parse("attrib=partial,unattributed", &f));
    CHECK(f.attribution[static_cast<std::size_t>(Attribution::Partial)]);
    CHECK(f.attribution[static_cast<std::size_t>(Attribution::Unattributed)]);
  }

  // --- rssi ------------------------------------------------------------------
  //
  // Strict inequalities, because "weaker than -90 dBm" is what an operator means and
  // `-90 <= rssi` would include the boundary and quietly change the answer.

  {
    FilterSpec f;
    REQUIRE(parse("rssi<-90", &f));
    CHECK(f.hasRssi);
    CHECK(f.rssiIsLowerBound);
    CHECK(filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                     Reason::FullyDecoded, -91, 1, Network::Unknown)));
    CHECK_MSG(!filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                           Reason::FullyDecoded, -90, 1, Network::Unknown)),
              "-90 dBm is not weaker than -90 dBm");

    FilterSpec g;
    REQUIRE(parse("rssi>-100", &g));
    CHECK(!g.rssiIsLowerBound);
    CHECK(filterMatches(g, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                     Reason::FullyDecoded, -99, 1, Network::Unknown)));
    CHECK(!filterMatches(g, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                      Reason::FullyDecoded, -100, 1, Network::Unknown)));

    FilterSpec h;
    REQUIRE(parse("rssi=-77", &h));
    CHECK(!h.rssiIsLowerBound);
    CHECK(filterMatches(h, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                     Reason::FullyDecoded, -77, 1, Network::Unknown)));
  }
  CHECK(rejects("rssi=loud"));
  CHECK(rejects("rssi<999"));

  // --- repetition -----------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("repeat>=5", &f));
    CHECK(f.hasRepeat);
    CHECK(filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                     Reason::FullyDecoded, -100, 5, Network::Unknown)));
    CHECK(!filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                      Reason::FullyDecoded, -100, 4, Network::Unknown)));
    CHECK(rejects("repeat>=many"));
  }

  // --- fingerprint -----------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("fp=4b2e1f0a9c8d7e6f", &f));
    CHECK(f.hasFingerprint);
    CHECK_EQ(f.fingerprint, 0x4b2e1f0a9c8d7e6fULL);

    Record r = makeRecord(Protocol::MeshCore, Attribution::Attributed, Reason::FullyDecoded,
                          -100, 1, Network::Unknown);
    r.fingerprint = 0x4b2e1f0a9c8d7e6fULL;
    CHECK(filterMatches(f, r));
    r.fingerprint = 0x0000000000000001ULL;
    CHECK(!filterMatches(f, r));
    CHECK(rejects("fp=zzzz"));
  }

  // --- text ------------------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("text=QUICK", &f));
    CHECK(f.hasText);
    CHECK_MSG(filterMatches(f, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                         Reason::FullyDecoded, -100, 1, Network::Unknown)),
              "text matching is case-insensitive");
    FilterSpec g;
    REQUIRE(parse("text=notpresent", &g));
    CHECK(!filterMatches(g, makeRecord(Protocol::MeshCore, Attribution::Attributed,
                                      Reason::FullyDecoded, -100, 1, Network::Unknown)));
    CHECK(rejects("text="));
  }

  // --- noise and corrupt ------------------------------------------------------

  {
    FilterSpec f;
    CHECK_MSG(!f.includeNoise, "noise is off by default");

    Record noisy = makeRecord(Protocol::Unknown, Attribution::Unattributed,
                              Reason::NoiseOrTooShort, -125, 1, Network::Unlisted);
    noisy.noise = true;
    // A disabled filter is "show me everything" and genuinely does include noise.
    CHECK_MSG(filterMatches(f, noisy), "a disabled filter passes noise; that is what 'off' means");

    // The claim that noise is excluded *by default* is about an enabled filter, so
    // the filter has to be enabled for the rule to apply.
    FilterSpec any;
    REQUIRE(parse("proto=mc", &any));
    CHECK_MSG(!filterMatches(any, noisy), "an enabled filter hides noise without being asked to");

    FilterSpec g;
    REQUIRE(parse("noise=true", &g));
    CHECK(filterMatches(g, noisy));

    Record bad = makeRecord(Protocol::MeshCore, Attribution::Attributed, Reason::FullyDecoded,
                            -100, 1, Network::MeshCoreEu868);
    bad.corrupt = true;
    CHECK_MSG(filterMatches(f, bad), "a corrupt frame is shown by default");
    FilterSpec h;
    REQUIRE(parse("corrupt=false", &h));
    CHECK(!h.includeCorrupt);
    CHECK(!filterMatches(h, bad));
  }

  // --- combinations narrow, and the description says so ------------------------

  {
    FilterSpec f;
    REQUIRE(parse("untraceable=true,proto=mc,rssi<-100,repeat>=3", &f));
    const std::string d = describeFilter(f);
    CHECK_MSG(d.find("untraceable") != std::string::npos, "");
    CHECK_MSG(d.find("proto=MC") != std::string::npos, "");
    CHECK_MSG(d.find("rssi<-100") != std::string::npos, "");
    CHECK_MSG(d.find("repeat>=3") != std::string::npos, "");

    Record r = makeRecord(Protocol::MeshCore, Attribution::Unattributed,
                          Reason::KnownSyncUnknownBody, -110, 4, Network::MeshCoreEu868);
    CHECK(filterMatches(f, r));

    r.repeatCount = 2;
    CHECK(!filterMatches(f, r));
    r.repeatCount = 4;
    r.link.rssiDbm = -80;
    CHECK(!filterMatches(f, r));
  }

  // --- description must reflect the exclusions, and say so when off -------------

  {
    // A disabled filter says so outright rather than pretending to be a filter.
    const std::string off = describeFilter(passAll());
    CHECK_MSG(off.find("off") != std::string::npos, "");
    CHECK_MSG(off.find("everything shown") != std::string::npos,
              "a disabled filter must not read like a narrowed one");

    // An enabled one states every exclusion it is applying, because an operator who
    // cannot see why a capture is empty will assume the band went quiet.
    FilterSpec f;
    REQUIRE(parse("proto=mc", &f));
    const std::string on = describeFilter(f);
    CHECK_MSG(on.find("noise=off") != std::string::npos, "");
    CHECK_MSG(on.find("proto=MC") != std::string::npos, "");
  }

  // --- serialise round-trips ------------------------------------------------------

  {
    FilterSpec f;
    REQUIRE(parse("untraceable=true,proto=mc", &f));
    const std::string s = serialiseFilter(f);
    CHECK_MSG(s.find("filter:") == std::string::npos,
              "the serialised form is a bare spec, not a description");

    FilterSpec back;
    char error[96];
    const bool ok = parseFilter(s.c_str(), &back, error, sizeof(error));
    CHECK_MSG(ok, s.c_str());
    CHECK(back.onlyUntraceable);
    CHECK(back.protocol[static_cast<std::size_t>(Protocol::MeshCore)]);
  }

  // --- malformed input is contained ------------------------------------------------

  {
    rejects("bogus=1");
    rejects("proto");
    CHECK_MSG(rejects(std::string(400, 'x').c_str()),
              "an over-long spec is refused rather than smashing a stack");
  }
  {
    // passAll() is the documented initial state and must equal a parse of "".
    FilterSpec a = passAll();
    FilterSpec b;
    CHECK(parse("", &b));
    CHECK_EQ(a.enabled, b.enabled);
    CHECK_EQ(a.onlyUntraceable, b.onlyUntraceable);
    CHECK_EQ(a.includeNoise, b.includeNoise);
    CHECK_EQ(a.includeCorrupt, b.includeCorrupt);
  }
}
