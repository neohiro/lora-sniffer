// SPDX-License-Identifier: MIT
//
// CommandLine -- one grammar, three transports.
//
// The brief asks for the sniffer to be drivable from a desktop tool, a phone, and
// the serial console, with easy commands. Three grammars would mean the command
// that was documented is not the one that works, and a phone app talking to a
// console that a human drives with the same verbs is the difference between a tool
// and a firmware project with three front ends.
//
// So: one line-oriented grammar, one parser, one result type, in portable code
// with no I/O. `tools/sniffctl.py` implements the *same* grammar in Python against
// the same vocabulary, and `tests/test_command_line.py` holds both sides to the same
// command list, so they cannot drift.
//
// Deliberate design points:
//
//   * **No output in the parser.** A command returns a `Command` describing what
//     was asked for; the caller decides how to answer. That is what lets the
//     desktop tool render JSON, the phone render a list, and the OLED render six
//     characters, all from the same parse.
//
//   * **Unknown commands are refused with a suggestion.** `devicse` gets
//     "did you mean: devices". A console that silently ignores a typo leaves the
//     operator staring at a list that did not change.
//
//   * **Arguments are bounded and never overflow.** Every string is copied into a
//     fixed buffer with a length check, because this parser's input is a serial port
//     and a serial port is a hostile place.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "sniffer/DeviceTable.hpp"

namespace sniff {

// Every command this firmware understands. The enum is the contract; the Python
// side holds the same list.
enum class CommandId : std::uint8_t {
  None = 0,
  Help,
  Stats,        // counters summary
  Memory,       // the memory report, including the working set
  Plan,         // what we are listening for, and where that came from
  Filter,       // set the filter, from a spec string
  Devices,      // the device list, in the requested order
  Dump,         // replay the ring log
  Tail,         // follow the capture stream (a mode, not a one-shot)
  Hex,          // include raw bytes in each line
  Text,         // allow decoded message text
  Beacon,       // build and (if armed) send a beacon
  Arm,
  Disarm,
  Emitted,
  Reset,
  Save,         // persist the configuration to this slot's filesystem
  Load,
};

const char* commandName(CommandId id);

// The device-list ordering requested by a `devices` command.
struct Command {
  CommandId id = CommandId::None;

  // A single argument, bounded. Most commands need exactly one: a filter spec, an
  // order name, a message. Commands that need more (a beacon's text plus a channel)
  // use the dedicated fields below, because a general argv array in a 512-byte
  // microcontroller is a vector for no benefit.
  static constexpr std::size_t kArgBytes = 96;
  char arg[kArgBytes] = {};

  // Numeric argument, and whether one was given. `hasNumber` is separate from
  // `number == 0` because zero is a legitimate value for a channel hash.
  bool hasNumber = false;
  std::uint32_t number = 0;

  // Device list ordering.
  Order order = Order::ShortestPath;

  // Beacon specifics.
  std::uint8_t beaconChannel = 0;
  std::uint8_t beaconRepeats = 3;
  std::uint32_t beaconIntervalMs = 5000;
  bool beaconOnMeshCore = true;
  bool beaconOnMeshtastic = false;
  bool beaconIsText = true;
};

struct ParseResult {
  bool ok = false;
  Command command;

  // Why it failed, for the operator. Never empty on failure: a parser that says
  // "error" is a parser the operator has to debug.
  char error[80] = {};

  // The nearest known command, when the failure was a typo. Empty otherwise.
  char suggestion[24] = {};
};

// Parse one line, with or without a trailing newline.
//
// Case-insensitive on the verb. Leading and trailing whitespace is trimmed; an
// empty line is not an error and yields a None command, because a console fed by a
// serial monitor sends them constantly.
ParseResult parseCommand(const char* line);

// Every verb, one per line. Used by `help` and, more importantly, by the Python
// test that holds the two implementations to the same list.
std::string commandList();

// Render a command back to its canonical line. Round-tripping is what makes a saved
// configuration readable, and the tests check that parse(render(x)) == x.
std::string renderCommand(const Command& c);

}  // namespace sniff
