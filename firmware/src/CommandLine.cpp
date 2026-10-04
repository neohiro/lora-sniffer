// SPDX-License-Identifier: MIT

#include "sniffer/CommandLine.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace sniff {
namespace {

struct Verb {
  CommandId id;
  const char* name;
  const char* help;
};

// The vocabulary. One table, and the help text lives next to the verb rather than
// in a separate block that can fall out of step with it.
constexpr Verb kVerbs[] = {
    {CommandId::Help, "help", "list every command"},
    {CommandId::Stats, "stats", "counters: protocols, reasons, unattributable ratio"},
    {CommandId::Memory, "memory", "flash, heap and the exact working set"},
    {CommandId::Plan, "plan", "what we are listening for, and where that came from"},
    {CommandId::Filter, "filter", "set the filter: filter untraceable=true,proto=mc"},
    {CommandId::Devices, "devices", "the node list: devices [shortest-path|last-seen|frames]"},
    {CommandId::Dump, "dump", "replay the retained capture ring"},
    {CommandId::Tail, "tail", "stream records as they arrive"},
    {CommandId::Hex, "hex", "include raw bytes in each line: hex on|off"},
    {CommandId::Text, "text", "allow decoded message text: text on|off"},
    {CommandId::Beacon, "beacon", "beacon <text> [mc|mt|both] [chan=N] [n=N] [ms=N]"},
    {CommandId::Arm, "arm", "allow this build to transmit (beacon builds only)"},
    {CommandId::Disarm, "disarm", "stop transmitting; the default after every reboot"},
    {CommandId::Emitted, "emitted", "how many beacons this build has put on the air"},
    {CommandId::Reset, "reset", "clear counters, the device list and the ring"},
    {CommandId::Save, "save", "persist the configuration to this slot's filesystem"},
    {CommandId::Load, "load", "read the configuration back from this slot"},
};

constexpr std::size_t kVerbCount = sizeof(kVerbs) / sizeof(kVerbs[0]);

char lowerAscii(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

bool equalsIgnoreCase(const char* a, const char* b) {
  if (a == nullptr || b == nullptr) return false;
  std::size_t i = 0;
  while (a[i] != '\0' && b[i] != '\0') {
    if (lowerAscii(a[i]) != lowerAscii(b[i])) return false;
    ++i;
  }
  return a[i] == '\0' && b[i] == '\0';
}

void fail(ParseResult* r, const char* fmt, const char* detail) {
  r->ok = false;
  // A refused command must not be executable. `c.id` is set before the argument is
  // validated, so without this a caller that checked only `ok` would still hold a
  // half-populated command -- and one whose argument is known to be wrong.
  r->command.id = CommandId::None;
  const int n = std::snprintf(r->error, sizeof(r->error), fmt, detail == nullptr ? "" : detail);
  if (n < 0) r->error[0] = '\0';
}

// The two-placeholder form, for a rejection where the verb and the offending token
// both belong in the message. "hex: wants on or off" without the token leaves the
// operator guessing at which of their arguments was wrong.
void fail2(ParseResult* r, const char* fmt, const char* verb, const char* value) {
  r->ok = false;
  r->command.id = CommandId::None;
  const int n = std::snprintf(r->error, sizeof(r->error), fmt, verb == nullptr ? "" : verb,
                              value == nullptr ? "" : value);
  if (n < 0) r->error[0] = '\0';
}

void copyArg(Command* c, const char* src, std::size_t cap) {
  std::size_t i = 0;
  for (; i + 1 < cap && src[i] != '\0'; ++i) c->arg[i] = src[i];
  c->arg[i] = '\0';
}

// The nearest verb by edit distance, used only for the "did you mean" hint. A
// suggestion that is wildly wrong is worse than none, so anything further than a
// couple of edits is reported as "no suggestion".
const char* nearestVerb(const char* word) {
  const char* best = nullptr;
  std::size_t bestDistance = 4;
  for (std::size_t i = 0; i < kVerbCount; ++i) {
    const char* candidate = kVerbs[i].name;
    const char* a = word;
    const char* b = candidate;
    std::size_t d = 0;
    while (*a != '\0' && *b != '\0' && d < bestDistance) {
      if (lowerAscii(*a) != lowerAscii(*b)) ++d;
      ++a;
      ++b;
    }
    while (*a != '\0' && d < bestDistance) {
      ++d;
      ++a;
    }
    while (*b != '\0' && d < bestDistance) {
      ++d;
      ++b;
    }
    if (d < bestDistance) {
      bestDistance = d;
      best = candidate;
    }
  }
  return best;
}

bool parseBoolWord(const char* w, bool* out) {
  if (equalsIgnoreCase(w, "on") || equalsIgnoreCase(w, "true") || equalsIgnoreCase(w, "1") ||
      equalsIgnoreCase(w, "yes")) {
    *out = true;
    return true;
  }
  if (equalsIgnoreCase(w, "off") || equalsIgnoreCase(w, "false") || equalsIgnoreCase(w, "0") ||
      equalsIgnoreCase(w, "no")) {
    *out = false;
    return true;
  }
  return false;
}

bool parseOrder(const char* w, Order* out) {
  if (equalsIgnoreCase(w, "shortest-path") || equalsIgnoreCase(w, "path") ||
      equalsIgnoreCase(w, "hops")) {
    *out = Order::ShortestPath;
    return true;
  }
  if (equalsIgnoreCase(w, "last-seen") || equalsIgnoreCase(w, "recent")) {
    *out = Order::LastSeen;
    return true;
  }
  if (equalsIgnoreCase(w, "frames") || equalsIgnoreCase(w, "most-frames")) {
    *out = Order::MostFrames;
    return true;
  }
  return false;
}

// Split into tokens in place. `rest` receives everything after the verb with
// leading whitespace trimmed, so a command whose argument is free text -- `filter`
// and `beacon` -- can take the remainder verbatim rather than one token of it.
// Split a line into the verb and its arguments, in place.
//
// The verb is `args[0]`: every caller dispatches on it. An earlier version stepped over
// the verb and counted only the words after it, which made a bare `stats` look exactly
// like an empty line -- the console reported success and did nothing, for every command
// that takes no arguments. It also read `args[0]` while `argCount` was zero, which is
// undefined behaviour and happened to read as an empty string.
//
// `rest` receives the text after the verb, copied out *before* the split, because the
// split writes NULs over the separating spaces. Commands that take a whole phrase --
// `filter untraceable=true, rssi<-90` -- need that phrase intact, spaces and all.
void tokenize(char* line, char** args, std::size_t maxArgs, std::size_t* argCount,
              char* rest, std::size_t restCap) {
  *argCount = 0;
  rest[0] = '\0';

  char* p = line;
  while (*p == ' ' || *p == '\t') ++p;
  if (*p == '\0') return;  // nothing but whitespace

  // The remainder first, while the buffer is still intact.
  char* q = p;
  while (*q != '\0' && *q != ' ' && *q != '\t') ++q;
  if (*q != '\0') {
    while (*q == ' ' || *q == '\t') ++q;
    std::size_t n = std::strlen(q);
    if (n >= restCap) n = restCap - 1;
    std::memcpy(rest, q, n);
    rest[n] = '\0';
  }

  while (*p != '\0' && *argCount < maxArgs) {
    while (*p == ' ' || *p == '\t') ++p;
    if (*p == '\0') break;
    args[(*argCount)++] = p;
    while (*p != '\0' && *p != ' ' && *p != '\t') ++p;
    if (*p != '\0') {
      *p = '\0';
      ++p;
    }
  }
}

// Pull a `key=N` out of a free-text argument list. `found` distinguishes "absent"
// from "present but unparseable", because a typo in a beacon modifier must be
// reported rather than silently treated as the default.

}  // namespace

const char* commandName(CommandId id) {
  for (std::size_t i = 0; i < kVerbCount; ++i) {
    if (kVerbs[i].id == id) return kVerbs[i].name;
  }
  return "none";
}

std::string commandList() {
  std::string s;
  for (std::size_t i = 0; i < kVerbCount; ++i) {
    s += kVerbs[i].name;
    s += "  ";
    s += kVerbs[i].help;
    if (i + 1 < kVerbCount) s += "\n";
  }
  return s;
}

ParseResult parseCommand(const char* line) {
  ParseResult r;
  r.ok = false;
  r.error[0] = '\0';
  r.suggestion[0] = '\0';

  if (line == nullptr) {
    std::snprintf(r.error, sizeof(r.error), "no line");
    return r;
  }

  // Bounded. This parser's input is a serial port, and a serial port is a hostile
  // place to be copying from.
  char work[Command::kArgBytes + 64];
  const std::size_t n = std::strlen(line);
  if (n >= sizeof(work)) {
    std::snprintf(r.error, sizeof(r.error), "line is longer than %u bytes",
                  static_cast<unsigned>(sizeof(work) - 1));
    return r;
  }
  for (std::size_t i = 0; i < n; ++i) {
    work[i] = (line[i] == '\n' || line[i] == '\r') ? '\0' : line[i];
  }
  work[n] = '\0';

  char* args[8];
  std::size_t argCount = 0;
  // The remainder after the verb, kept in its own buffer: `tokenize` NUL-terminates
  // arguments in place, so a pointer back into `work` would come back truncated at the
  // first argument.
  char rest[Command::kArgBytes + 64] = {};
  tokenize(work, args, 8, &argCount, rest, sizeof(rest));

  // An empty line is not an error. A serial monitor sends them constantly and a
  // console that reports "unknown command" for each one is unusable.
  if (argCount == 0 || args[0][0] == '\0') {
    r.command.id = CommandId::None;
    r.ok = true;
    return r;
  }

  const char* verb = args[0];
  const Verb* verbEntry = nullptr;
  for (std::size_t i = 0; i < kVerbCount; ++i) {
    if (equalsIgnoreCase(verb, kVerbs[i].name)) {
      verbEntry = &kVerbs[i];
      break;
    }
  }

  if (verbEntry == nullptr) {
    fail(&r, "unknown command: %s", verb);
    const char* near = nearestVerb(verb);
    if (near != nullptr) {
      std::snprintf(r.suggestion, sizeof(r.suggestion), "did you mean: %s", near);
    }
    return r;
  }

  Command& c = r.command;
  c.id = verbEntry->id;
  r.ok = true;

  switch (c.id) {
    case CommandId::Help:
    case CommandId::Stats:
    case CommandId::Memory:
    case CommandId::Plan:
    case CommandId::Dump:
    case CommandId::Tail:
    case CommandId::Arm:
    case CommandId::Disarm:
    case CommandId::Emitted:
    case CommandId::Reset:
    case CommandId::Save:
    case CommandId::Load:
      // No arguments. An extra one is ignored rather than refused, because a client
      // that appends one by reflex should still work.
      break;

    case CommandId::Filter:
      // The whole remainder is the spec: `filter untraceable=true, rssi<-90` is one
      // argument, not two.
      if (rest[0] != '\0') copyArg(&c, rest, sizeof(c.arg));
      break;

    case CommandId::Hex:
    case CommandId::Text:
      if (argCount >= 2) {
        bool on = true;
        if (!parseBoolWord(args[1], &on)) {
          fail2(&r, "%s wants on or off, got: %s", verb, args[1]);
          return r;
        }
        copyArg(&c, on ? "on" : "off", sizeof(c.arg));
      } else {
        copyArg(&c, "toggle", sizeof(c.arg));
      }
      break;

    case CommandId::Devices:
      if (argCount >= 2 && !parseOrder(args[1], &c.order)) {
        fail2(&r, "%s wants shortest-path, last-seen or frames, got: %s", verb, args[1]);
        return r;
      }
      copyArg(&c, orderName(c.order), sizeof(c.arg));
      break;

    case CommandId::Beacon: {
      if (rest[0] == '\0') {
        fail(&r, "beacon wants text, e.g. beacon hello both chan=8F n=5", nullptr);
        return r;
      }

      // Tokens, each with its length.
      //
      // `rest` is whitespace-separated and not NUL-terminated per token, so every
      // comparison below is length-bounded. Reading a token with strcmp/equalsIgnoreCase
      // ran on into the *next* token, which is how "both chan=8F" failed to recognise
      // its own network selector.
      struct Tok {
        const char* p;
        std::size_t n;
      };
      Tok toks[16];
      std::size_t nTok = 0;
      {
        const char* q = rest;
        while (*q != '\0' && nTok < (sizeof(toks) / sizeof(toks[0]))) {
          while (*q == ' ' || *q == ',') ++q;
          if (*q == '\0') break;
          toks[nTok].p = q;
          while (*q != '\0' && *q != ' ' && *q != ',') ++q;
          toks[nTok].n = static_cast<std::size_t>(q - toks[nTok].p);
          ++nTok;
        }
      }

      auto tokenIs = [&](std::size_t i, const char* lit) {
        const std::size_t l = std::strlen(lit);
        return toks[i].n == l && std::strncmp(toks[i].p, lit, l) == 0;
      };
      auto tokenHasKey = [&](std::size_t i, const char* key) {
        const std::size_t l = std::strlen(key);
        return toks[i].n > l && std::strncmp(toks[i].p, key, l) == 0;
      };

      // Modifiers and the network selector are recognised only in the *trailing* run of
      // tokens, and only for as long as every token in that run is one of them.
      //
      // Anything looser eats words out of the message: "beacon send n=1 to me" quietly
      // became "send to me". Silently shortening what an operator asked to be put on the
      // air is a worse failure than making them rephrase to reach the repeat count.
      std::size_t runStart = nTok;
      while (runStart > 0) {
        const std::size_t i = runStart - 1;
        const bool selectable =
            tokenIs(i, "mc") || tokenIs(i, "mt") || tokenIs(i, "both");
        const bool modifier = tokenHasKey(i, "chan=") || tokenHasKey(i, "n=") ||
                              tokenHasKey(i, "ms=");
        if (!selectable && !modifier) break;
        --runStart;
      }

      std::uint32_t chan = 0;
      std::uint32_t repeats = 0;
      std::uint32_t interval = 0;
      char net[8] = {};

      for (std::size_t i = runStart; i < nTok; ++i) {
        if (tokenIs(i, "mc") || tokenIs(i, "mt") || tokenIs(i, "both")) {
          for (std::size_t k = 0; k < toks[i].n && k + 1 < sizeof(net); ++k) {
            net[k] = toks[i].p[k];
          }
          net[toks[i].n < sizeof(net) ? toks[i].n : sizeof(net) - 1] = '\0';
          continue;
        }

const char* key = nullptr;
        std::uint32_t* slot = nullptr;
        const char* complaint = nullptr;
        // `chan` and `n` land in a uint8_t. Accepting a larger number and truncating it
        // would put a beacon on channel 0xE8 when the operator asked for 1000, and the
        // only evidence would be silence.
        long maxVal = 65535;
        if (tokenHasKey(i, "chan=")) {
          key = "chan=";
          slot = &chan;
          maxVal = 255;
          complaint = "beacon: chan= wants a number from 0 to 255";
        } else if (tokenHasKey(i, "n=")) {
          key = "n=";
          slot = &repeats;
          maxVal = 255;
          complaint = "beacon: n= wants a repeat count from 0 to 255";
        } else if (tokenHasKey(i, "ms=")) {
          key = "ms=";
          slot = &interval;
          complaint = "beacon: ms= wants an interval in milliseconds";
        }
        if (key == nullptr || slot == nullptr) continue;

        // Copy the digits out, bounded by the token's length: the token is not
        // NUL-terminated, so strtol would stop at the following space and report a
        // perfectly good value as malformed.
        //
        // `key` already includes the '=', so the digits start at klen -- not klen + 1.
        char digits[12];
        const std::size_t klen = std::strlen(key);
        const std::size_t dlen = toks[i].n - klen;
        if (dlen == 0 || dlen >= sizeof(digits)) {
          fail(&r, complaint, nullptr);
          return r;
        }
        std::memcpy(digits, toks[i].p + klen, dlen);
        digits[dlen] = '\0';

        // Decimal first, hex second: `n=5` and `ms=7000` are counts, and a MeshCore
        // channel hash is conventionally written in hex -- the help text for this very
        // command says `chan=8F`. Decimal first keeps "10" meaning ten.
        char* end = nullptr;
        long v = std::strtol(digits, &end, 10);
        if (end == digits || (end != nullptr && *end != '\0')) {
          end = nullptr;
          v = std::strtol(digits, &end, 16);
        }
        if (end == digits || (end != nullptr && *end != '\0')) {
          fail(&r, complaint, nullptr);
          return r;
        }
        if (v < 0 || v > maxVal) {
          fail(&r, complaint, nullptr);
          return r;
        }
        *slot = static_cast<std::uint32_t>(v);
      }

      // Everything before the modifier run is the message, reassembled with single
      // spaces so that exactly what the operator typed is what gets transmitted.
      char text[Command::kArgBytes];
      std::size_t w = 0;
      for (std::size_t i = 0; i < runStart; ++i) {
        if (w > 0 && w + 1 < sizeof(text)) text[w++] = ' ';
        for (std::size_t k = 0; k < toks[i].n && w + 1 < sizeof(text); ++k) {
          text[w] = toks[i].p[k];
          ++w;
        }
      }
      text[w] = '\0';

      if (w == 0) {
        fail(&r, "beacon: no text left after the modifiers", nullptr);
        return r;
      }
      copyArg(&c, text, sizeof(c.arg));

      // Default: MeshCore only. It is the mesh a Heltec V4 running this firmware is
      // most likely part of, and a beacon on a network the operator did not name is a
      // beacon nobody asked for.
      c.beaconOnMeshCore = true;
      c.beaconOnMeshtastic = false;
      if (equalsIgnoreCase(net, "mt")) {
        c.beaconOnMeshCore = false;
        c.beaconOnMeshtastic = true;
      } else if (equalsIgnoreCase(net, "both")) {
        c.beaconOnMeshCore = true;
        c.beaconOnMeshtastic = true;
      }
      c.beaconIsText = true;
      c.beaconChannel = static_cast<std::uint8_t>(chan);
      c.beaconRepeats = (repeats == 0) ? static_cast<std::uint8_t>(3)
                                       : static_cast<std::uint8_t>(repeats);
      c.beaconIntervalMs = (interval == 0) ? 5000u : interval;
      break;
    }
    default:
      break;
  }

  return r;
}

std::string renderCommand(const Command& c) {
  std::string s = commandName(c.id);
  switch (c.id) {
    case CommandId::Filter:
    case CommandId::Beacon:
      if (c.arg[0] != '\0') {
        s += " ";
        s += c.arg;
      }
      break;
    case CommandId::Devices:
      s += " ";
      s += orderName(c.order);
      break;
    case CommandId::Hex:
    case CommandId::Text:
      if (c.arg[0] != '\0' && std::strcmp(c.arg, "toggle") != 0) {
        s += " ";
        s += c.arg;
      }
      break;
    default:
      break;
  }
  return s;
}

}  // namespace sniff
