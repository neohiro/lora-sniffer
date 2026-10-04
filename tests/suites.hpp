// SPDX-License-Identifier: MIT

#pragma once

#include <string>

// A partition table as it exists on disk, so the suites validate the artefacts
// this repo actually ships rather than a copy that can quietly drift away from
// them. main.cpp reads the files and hands them over.
struct PartitionTableUnderTest {
  std::string path;  // for failure messages
  std::string csv;
  bool loaded = false;
};

void suite_rf_plan();
void suite_protocol();
void suite_provenance();
void suite_plan_registry();
void suite_classifier();
void suite_meshcore_frame();
void suite_meshcore_payload();
void suite_meshtastic_frame();
void suite_lorawan_frame();
void suite_fingerprint();
void suite_filter();
void suite_record();
void suite_jsonl();
void suite_wire();
void suite_counters();
void suite_capture();
void suite_slot_plan();
void suite_beacon();
void suite_command_line();
void suite_tx_lockout();
void suite_plan_source();
void suite_partition_csv(const PartitionTableUnderTest* tables, int count);
