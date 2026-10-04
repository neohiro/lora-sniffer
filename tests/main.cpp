// SPDX-License-Identifier: MIT
//
// One binary, one exit code. The same binary is what CI runs, so there is no
// second definition of "passing" to drift away from the first.

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "harness.hpp"
#include "suites.hpp"

namespace {

bool readFile(const std::string& path, std::string* out) {
  std::ifstream in(path.c_str(), std::ios::binary);
  if (!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  *out = ss.str();
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  // Unbuffered. A test binary that crashes takes its buffered output with it,
  // which is precisely when the output is most wanted.
  std::setvbuf(stdout, nullptr, _IONBF, 0);

  // Default the partition directory so `python tools/gate.py` works from the repo
  // root, but let CI or a caller point it elsewhere.
  const std::string partDir = argc > 1 ? std::string(argv[1]) : std::string("firmware/partitions");

  const char* names[] = {"triboot.csv", "snifferboot.csv"};
  std::vector<PartitionTableUnderTest> tables;
  for (const char* n : names) {
    PartitionTableUnderTest t;
    t.path = partDir + "/" + n;
    t.loaded = readFile(t.path, &t.csv);
    tables.push_back(t);
  }

  std::printf("lora-sniffer :: portable logic gate\n");

  suite_rf_plan();
  suite_protocol();
  suite_provenance();
  suite_plan_registry();
  suite_classifier();
  suite_meshcore_frame();
  suite_meshcore_payload();
  suite_meshtastic_frame();
  suite_lorawan_frame();
  suite_fingerprint();
  suite_filter();
  suite_record();
  suite_jsonl();
  suite_wire();
  suite_counters();
  suite_capture();
  suite_slot_plan();
  suite_beacon();
  suite_command_line();
  suite_tx_lockout();
  suite_plan_source();
  suite_partition_csv(tables.data(), static_cast<int>(tables.size()));

  std::printf("\n%d checks, %d failed\n", harness::checks(), harness::failures());
  if (harness::failures() == 0) {
    std::printf("PASS\n");
    return 0;
  }
  std::printf("FAIL\n");
  return 1;
}
