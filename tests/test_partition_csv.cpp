// SPDX-License-Identifier: MIT
//
// The shipped partition tables, validated as files on disk.
//
// main.cpp reads the real CSVs from firmware/partitions and hands them here, so
// this suite checks the artefacts this repository actually ships rather than a copy
// that can quietly drift away from them. A partition table that is wrong in a way
// the code does not model is the failure that presents as a board that is simply
// dead, with no log, so the checks here are deliberately blunt and independent of
// SlotPlan's own arithmetic.

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "harness.hpp"
#include "sniffer/SlotPlan.hpp"
#include "suites.hpp"

using namespace sniff;

namespace {

struct Part {
  std::string label;
  std::string type;
  std::string subtype;
  std::size_t offset = 0;
  std::size_t size = 0;
  bool blank = false;
  std::size_t line = 0;
};

std::size_t parseSize(const std::string& text, bool* ok) {
  *ok = false;
  if (text.empty()) return 0;
  std::size_t mult = 1;
  std::string t = text;
  const char last = t[t.size() - 1];
  if (last == 'K' || last == 'k') {
    mult = 1024;
    t = t.substr(0, t.size() - 1);
  } else if (last == 'M' || last == 'm') {
    mult = 1024 * 1024;
    t = t.substr(0, t.size() - 1);
  }
  int base = 10;
  if (t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X')) {
    base = 16;
    t = t.substr(2);
  }
  if (t.empty()) return 0;
  char* end = nullptr;
  const unsigned long long v = std::strtoull(t.c_str(), &end, base);
  if (end == nullptr || *end != '\0') return 0;
  *ok = true;
  return static_cast<std::size_t>(v) * mult;
}

std::string trim(const std::string& s) {
  std::size_t a = 0;
  std::size_t b = s.size();
  while (a < b && (s[a] == ' ' || s[a] == '\t')) ++a;
  while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t')) --b;
  return s.substr(a, b - a);
}

std::vector<Part> parseCsv(const std::string& csv, std::vector<std::string>* problems) {
  std::vector<Part> parts;
  std::size_t lineNo = 0;
  std::size_t pos = 0;

  while (pos <= csv.size()) {
    const std::size_t nl = csv.find('\n', pos);
    const std::string raw = csv.substr(pos, (nl == std::string::npos ? csv.size() : nl) - pos);
    pos = (nl == std::string::npos) ? csv.size() + 1 : nl + 1;
    ++lineNo;

    const std::string line = trim(raw);
    if (line.empty() || line[0] == '#') continue;

    std::vector<std::string> fields;
    std::size_t start = 0;
    while (true) {
      const std::size_t comma = line.find(',', start);
      if (comma == std::string::npos) {
        fields.push_back(trim(line.substr(start)));
        break;
      }
      fields.push_back(trim(line.substr(start, comma - start)));
      start = comma + 1;
    }

    if (fields.size() < 5) {
      problems->push_back("line " + std::to_string(lineNo) + ": fewer than five fields");
      continue;
    }

    Part p;
    p.line = lineNo;
    p.label = fields[0];
    p.type = fields[1];
    p.subtype = fields[2];
    bool okOffset = false;
    p.offset = parseSize(fields[3], &okOffset);
    p.blank = fields[4].empty();
    p.size = p.blank ? 0 : parseSize(fields[4], &okOffset);
    if (!okOffset) {
      problems->push_back("line " + std::to_string(lineNo) + ": unparseable number in " + p.label);
      continue;
    }
    parts.push_back(p);
  }
  return parts;
}

const Part* find(const std::vector<Part>& parts, const char* label) {
  for (const Part& p : parts) {
    if (p.label == label) return &p;
  }
  return nullptr;
}

}  // namespace

void suite_partition_csv(const PartitionTableUnderTest* tables, int count) {
  harness::suite("shipped partition tables");

  CHECK_MSG(count > 0, "main.cpp must hand over at least one table");
  if (count == 0) return;

  for (int i = 0; i < count; ++i) {
    const PartitionTableUnderTest& t = tables[i];
    REQUIRE_MSG(t.loaded, t.path.c_str());

    std::vector<std::string> problems;
    const std::vector<Part> parts = parseCsv(t.csv, &problems);
    for (const std::string& p : problems) {
      CHECK_MSG(false, p.c_str());
    }
    REQUIRE_MSG(parts.size() >= 4, t.path.c_str());

    // --- the fixed region ---------------------------------------------------
    //
    // The bootloader and the partition table are deliberately NOT rows here.
    //
    // The bootloader is flashed at 0x0 out of band, and the partition table occupies
    // the single 4 KB sector at 0x8000 whether or not a row claims it. The generator
    // used to emit rows for both, and the 0x8000 row is read as overlapping the table's
    // own extent -- `gen_esp32part.py` refuses the whole file with "first partition
    // offset 0x0 overlaps end of partition table 0x9000". That is a build failure on
    // the chip, so nothing here may depend on those rows existing.
    const Part* ota = find(parts, "otadata");
    const Part* nvs = find(parts, "nvs");
    const Part* dump = find(parts, "coredump");
    CHECK_MSG(find(parts, "bootloader") == nullptr && find(parts, "partition_tbl") == nullptr,
              "the bootloader and the partition table are not rows; listing the table "
              "at 0x8000 makes the chip's own generator reject the file");
    CHECK_MSG(ota != nullptr && nvs != nullptr,
              "otadata and nvs sit below the slots and must be present");
    CHECK_MSG(dump != nullptr, "the coredump lives below the slots so capacity is a "
                               "subtraction rather than a moving target");

    // Nothing may be placed at or below the sector the partition table occupies.
    for (const Part& p : parts) {
      CHECK_MSG(p.offset >= kPartitionTableOffset + 0x1000,
                "every partition must start above 0x9000: the table itself is the "
                "4 KB sector at 0x8000");
    }

    if (ota != nullptr) CHECK_EQ(ota->offset, kOtadataOffset);
    if (nvs != nullptr) CHECK_EQ(nvs->offset, kNvsOffset);
    if (dump != nullptr) CHECK_EQ(dump->offset, kCoredumpOffset);

    // --- no overlap, in address order ---------------------------------------
    //
    // Deliberately not reusing SlotPlan::validate(). This check exists because the
    // shipped file is the thing the bootloader reads, and a mistake here presents as
    // a board that is simply dead with no log anywhere.

    std::vector<const Part*> ordered;
    for (const Part& p : parts) {
      if (!p.blank) ordered.push_back(&p);
    }
    for (std::size_t a = 0; a < ordered.size(); ++a) {
      for (std::size_t b = a + 1; b < ordered.size(); ++b) {
        const Part* lo = ordered[a]->offset <= ordered[b]->offset ? ordered[a] : ordered[b];
        const Part* hi = lo == ordered[a] ? ordered[b] : ordered[a];
        CHECK_MSG(lo->offset + lo->size <= hi->offset,
                  lo->label + " overlaps " + hi->label + " in " + t.path);
      }
    }

    // --- everything inside the flash -----------------------------------------

    const std::size_t flash = kDefaultFlashBytes;
    for (const Part& p : parts) {
      if (p.blank) continue;
      CHECK_MSG(p.offset + p.size <= flash,
                p.label + " ends past the end of flash in " + t.path);
      CHECK_MSG(p.offset % 0x1000 == 0, p.label + " is not 4KB aligned in " + t.path);
      if (p.type == "app" && p.size != 0) {
        CHECK_MSG(p.offset % kAppAlignment == 0,
                  p.label + " is not 64KB aligned. The bootloader refuses this and reports "
                            "nothing, so the board looks simply dead.");
      }
    }

    // --- labels are unique ---------------------------------------------------

    for (std::size_t a = 0; a < parts.size(); ++a) {
      for (std::size_t b = a + 1; b < parts.size(); ++b) {
        CHECK_MSG(parts[a].label != parts[b].label,
                  "duplicate label " + parts[a].label + " in " + t.path);
      }
    }

    // --- slot geometry is arithmetic ------------------------------------------
    //
    // Slot n at the address SlotPlan computes, whether the table declares three
    // slots or five. This is the property that makes rewriting the table safe.

    std::vector<const Part*> appSlots;
    for (const Part& p : parts) {
      if (p.type == "app" && p.label.size() > 4 && p.label.compare(0, 4, "ota_") == 0) {
        appSlots.push_back(&p);
      }
    }
    REQUIRE_MSG(!appSlots.empty(), t.path.c_str());

    for (std::size_t s = 0; s < appSlots.size(); ++s) {
      const Part* p = appSlots[s];
      CHECK_MSG(p->offset == slotOffset(static_cast<std::uint8_t>(s)),
                p->label + " is not at the address the geometry computes, in " + t.path);
      CHECK_MSG(p->size == kSlotAppBytes, p->label + " has the wrong app size in " + t.path);
    }

    // Each app slot is followed by its own filesystem, and nothing is shared.
    for (std::size_t s = 0; s < appSlots.size(); ++s) {
      const Role role = static_cast<Role>(s);
      const char* wantLabel = slotFsLabel(role);
      const char* wantType = slotFsType(role);

      const Part* fs = find(parts, wantLabel);
      if (fs == nullptr) {
        // The sniffer-only table legitimately has no MeshCore filesystem.
        if (role == Role::MeshCore && appSlots.size() == 1 && appSlots[0]->label == "ota_0" &&
            find(parts, "ota_0") != nullptr && t.path.find("sniffer") != std::string::npos) {
          continue;
        }
        CHECK_MSG(false, std::string("missing filesystem ") + wantLabel + " in " + t.path);
        continue;
      }
      CHECK_MSG(fs->offset == slotFsOffset(static_cast<std::uint8_t>(s)),
                std::string(fs->label) + " is not at the address the geometry computes");
      CHECK_MSG(fs->size == kSlotFsBytes, std::string(fs->label) + " has the wrong size");
      CHECK_MSG(fs->subtype == wantType,
                std::string(fs->label) + " is declared " + fs->subtype + ", expected " +
                    wantType + ". Meshtastic mounts LittleFS and MeshCore mounts SPIFFS; "
                               "handing either side the other's filesystem makes it format "
                               "the wrong one on boot and lose the other's settings.");
    }

    // --- what the table is for -------------------------------------------------

    if (t.path.find("triboot") != std::string::npos) {
      // The MeshCore + Meshtastic + sniffer table. Three slots, all isolated.
      CHECK_MSG(appSlots.size() >= 3, "the three-slot table must declare three slots");
      CHECK(find(parts, "fs_meshcore") != nullptr);
      CHECK(find(parts, "fs_meshtastic") != nullptr);
      CHECK_MSG(find(parts, "fs_sniffer") != nullptr,
                "the sniffer's slot is the whole point of this table");
      const LayoutReport report = validateForSniffer(Layout::Shared);
      CHECK_MSG(report.ok(), report.detail);
    }
    if (t.path.find("snifferboot") != std::string::npos) {
      // Standalone: the sniffer alone in slot 0, so a board can be flashed with
      // nothing but this firmware and work.
      CHECK_MSG(appSlots.size() == 1, "the standalone table declares exactly one slot");
      const Part* ota0 = find(parts, "ota_0");
      REQUIRE(ota0 != nullptr);
      CHECK_MSG(ota0->offset == kFirstSlotOffset, "and it is slot 0");
    }

    // --- the two renderers agree ----------------------------------------------
    //
    // There are two implementations of this table: `renderSlots()` here and
    // `tools/gen_layouts.py`, which produces the shipped file. They drifted, and the
    // drift is invisible from either side alone: the C++ renderer emitted a
    // `partition_tbl` row at 0x8000 and an `otadata` *subtype*, both of which the chip's
    // generator rejects, while every test that read the shipped file passed and every
    // test that read the renderer asserted the wrong things.
    //
    // So compare the renderer's rows against the shipped file's rows directly. Comments
    // and column padding are allowed to differ; the data may not.
    {
      const Layout layout = t.path.find("snifferboot") != std::string::npos
                                ? Layout::Standalone
                                : Layout::Shared;
      std::vector<std::string> renderedProblems;
      const std::vector<Part> rendered =
          parseCsv(renderSlots(layout, slotsIn(layout)), &renderedProblems);
      for (const std::string& p : renderedProblems) {
        CHECK_MSG(false, (std::string("the C++ renderer emitted an unparseable row: ") + p).c_str());
      }
      REQUIRE_MSG(rendered.size() == parts.size(),
                  std::string("the C++ renderer and the shipped file disagree on the row "
                              "count: ") +
                      t.path);
      for (std::size_t a = 0; a < parts.size(); ++a) {
        CHECK_MSG(parts[a].label == rendered[a].label,
                  parts[a].label + " vs " + rendered[a].label + " in " + t.path);
        CHECK_MSG(parts[a].type == rendered[a].type,
                  parts[a].label + ": type differs between renderer and file in " + t.path);
        CHECK_MSG(parts[a].subtype == rendered[a].subtype,
                  parts[a].label + ": subtype " + parts[a].subtype + " vs " +
                      rendered[a].subtype + " in " + t.path);
        CHECK_MSG(parts[a].offset == rendered[a].offset,
                  parts[a].label + ": offset differs between renderer and file in " + t.path);
        CHECK_MSG(parts[a].size == rendered[a].size,
                  parts[a].label + ": size differs between renderer and file in " + t.path);
      }
    }
  }
}
