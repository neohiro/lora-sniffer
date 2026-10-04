// SPDX-License-Identifier: MIT
//
// The listen plan and the evidence the radio gives about one frame.
//
// The through-line of this suite is the distinction the whole project rests on:
// what we *configured* versus what the radio *reports*. A test that let those
// blur would be worse than no test, because it would license a firmware that
// prints its configuration as though it were a measurement.

// test_rf_plan.cpp used strcmp() and relied on another header pulling in <cstring>.
// That is fine on the machine that wrote it and fails on the Linux runner with
// "'strcmp' was not declared in this scope", which is what a build matrix is for.
#include <cstring>

#include "harness.hpp"
#include "sniffer/PlanRegistry.hpp"
#include "sniffer/Protocol.hpp"
#include "sniffer/RfPlan.hpp"

using namespace sniff;

namespace {

RfParams eu868() {
  RfParams p;
  p.frequencyMHz = 869.525f;
  p.bandwidthKHz = 250.0f;
  p.spreadingFactor = 11;
  p.codingRateDenominator = 5;
  return p;
}

RfParams us915() {
  RfParams p;
  p.frequencyMHz = 910.525f;
  p.bandwidthKHz = 125.0f;
  p.spreadingFactor = 7;
  return p;
}

}  // namespace

void suite_rf_plan() {
  harness::suite("RfPlan");

  // --- plausibility --------------------------------------------------------

  CHECK(rfParamsPlausible(eu868()));
  CHECK_MSG(rfParamsPlausible(eu868()), "the EU_868 MeshCore/Meshtastic plan must be valid");

  {
    RfParams p = eu868();
    p.spreadingFactor = 4;
    CHECK(!rfParamsPlausible(p));
    p.spreadingFactor = 13;
    CHECK_MSG(!rfParamsPlausible(p), "SF13 is not in the SX126x LoRa range");
    p.spreadingFactor = 0;
    CHECK(!rfParamsPlausible(p));
  }
  {
    RfParams p = eu868();
    p.codingRateDenominator = 4;
    CHECK(!rfParamsPlausible(p));
    p.codingRateDenominator = 9;
    CHECK(!rfParamsPlausible(p));
  }
  {
    RfParams p = eu868();
    p.bandwidthKHz = 0.0f;
    CHECK(!rfParamsPlausible(p));
    p.bandwidthKHz = 1000.0f;
    CHECK(!rfParamsPlausible(p));
    p.bandwidthKHz = 7.0f;
    CHECK(rfParamsPlausible(p));
    p.bandwidthKHz = 500.0f;
    CHECK(rfParamsPlausible(p));
  }
  {
    RfParams p = eu868();
    p.frequencyMHz = 100.0f;
    CHECK(!rfParamsPlausible(p));
    p.frequencyMHz = 1000.0f;
    CHECK(!rfParamsPlausible(p));
  }

  // --- plan comparison -----------------------------------------------------

  CHECK(sameRfPlan(eu868(), eu868()));

  {
    // Rounding artefacts must not split one network's traffic into two.
    RfParams a = eu868();
    RfParams b = eu868();
    b.frequencyMHz = 869.5253f;
    CHECK_MSG(sameRfPlan(a, b), "0.3 kHz of drift is a rounding artefact, not a new network");
    b.frequencyMHz = 869.5300f;
    CHECK_MSG(!sameRfPlan(a, b), "5 kHz is a different frequency and must not match");
  }
  {
    // The US_915 finding from the bridge repo: the two community defaults are
    // 3.65 MHz apart there, so a sniffer on one hears nothing of the other.
    RfParams mt = us915();
    mt.frequencyMHz = 906.875f;
    RfParams mc = us915();
    mc.frequencyMHz = 910.525f;
    CHECK_MSG(!sameRfPlan(mt, mc), "US_915 defaults are 3.65 MHz apart and must not compare equal");
  }
  {
    RfParams a = eu868();
    RfParams b = eu868();
    b.spreadingFactor = 12;
    CHECK(!sameRfPlan(a, b));
    b = eu868();
    b.bandwidthKHz = 125.0f;
    CHECK(!sameRfPlan(a, b));
    b = eu868();
    b.codingRateDenominator = 8;
    CHECK(!sameRfPlan(a, b));
  }

  // --- keys and descriptions ----------------------------------------------

  CHECK(planKey(eu868()) == "869.525/250/SF11/4-5");
  CHECK_MSG(planKey(eu868()) == "869.525/250/SF11/4-5",
            "the plan key is the operator's grouping key and must be stable");

  {
    RfParams p = eu868();
    p.spreadingFactor = 7;
    p.bandwidthKHz = 125.0f;
    p.codingRateDenominator = 8;
    CHECK(planKey(p) == "869.525/125/SF7/4-8");
  }

  {
    const std::string d = describeRf(eu868());
    CHECK(d.find("869.525MHz") != std::string::npos);
    CHECK(d.find("250kHz") != std::string::npos);
    CHECK(d.find("SF11") != std::string::npos);
    CHECK(d.find("4/5") != std::string::npos);
  }
  {
    RfParams p = eu868();
    p.crcOn = false;
    CHECK(describeRf(p).find("nocrc") != std::string::npos);
  }

  // --- evidence ------------------------------------------------------------

  CHECK(strcmp(checkName(Check::Passed), "ok") == 0);
  CHECK(strcmp(checkName(Check::Failed), "bad") == 0);
  CHECK(strcmp(checkName(Check::Untested), "untested") == 0);

  {
    // Below the noise floor is noise, and must be labelled as such rather than
    // being allowed into the protocol statistics.
    LinkEvidence e;
    e.rssiDbm = -100;
    e.crcCheck = Check::Passed;
    CHECK(!likelyNoise(e));

    e.rssiDbm = kNoiseFloorDbm - 1;
    CHECK_MSG(likelyNoise(e), "-121 dBm is below the floor");

    e.rssiDbm = -100;
    e.syncWordCheck = Check::Failed;
    CHECK_MSG(likelyNoise(e), "a frame refused at the preamble never became a payload");

    e.syncWordCheck = Check::Untested;
    e.headerCheck = Check::Failed;
    CHECK(likelyNoise(e));

    // Untested is not Failed. A radio path that never reads the header bit has not
    // rejected anything, and treating that as a rejection would discard every
    // frame on a perfectly healthy setup.
    e.headerCheck = Check::Untested;
    e.crcCheck = Check::Passed;
    CHECK_MSG(!likelyNoise(e), "untested must not be read as failed");
  }

  {
    LinkEvidence e;
    e.crcCheck = Check::Passed;
    CHECK(strongestCheck(e) == Check::Passed);

    // A failure anywhere outranks a pass elsewhere: a frame that failed one check
    // was not a good frame, whatever else it scored.
    e.crcCheck = Check::Failed;
    e.headerCheck = Check::Passed;
    CHECK_MSG(strongestCheck(e) == Check::Failed, "a CRC failure dominates a header pass");

    e = LinkEvidence{};
    CHECK(strongestCheck(e) == Check::Untested);
    e.headerCheck = Check::Passed;
    CHECK(strongestCheck(e) == Check::Passed);
  }

  {
    LinkEvidence e;
    e.rssiDbm = -103;
    e.snrDb = -7.5f;
    e.syncWordAvailable = true;
    e.syncWord = 0x12;
    e.syncWordCheck = Check::Passed;
    e.headerCheck = Check::Passed;
    e.crcCheck = Check::Passed;
    const std::string s = describeEvidence(e);
    CHECK(s.find("sync 0x12(ok)") != std::string::npos);
    CHECK(s.find("rssi -103") != std::string::npos);

    e.syncWordAvailable = false;
    CHECK_MSG(describeEvidence(e).find("sync n/a") != std::string::npos,
              "an unavailable sync byte must say so rather than print 0x00");
  }

  // --- sync words ----------------------------------------------------------

  CHECK(isWildcardSync(0x00));
  CHECK(!isWildcardSync(0x12));
  CHECK(fromSyncWord(0x12) == Protocol::MeshCore);
  CHECK(fromSyncWord(0x2B) == Protocol::Meshtastic);
  CHECK(fromSyncWord(0x42) == Protocol::Reticulum);
  CHECK(fromSyncWord(0x34) == Protocol::LoRaWan);
  CHECK(fromSyncWord(0x00) == Protocol::Unknown);
  CHECK_MSG(fromSyncWord(0x99) == Protocol::Unknown,
            "an unrecognised sync word must stay Unknown, never default to a mesh");
}
