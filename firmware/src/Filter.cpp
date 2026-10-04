// SPDX-License-Identifier: MIT

#include "sniffer/Filter.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "sniffer/Fingerprint.hpp"

namespace sniff {
namespace {

constexpr std::size_t kProtocolCount = 6;
constexpr std::size_t kNetworkCount = 6;
constexpr std::size_t kAttributionCount = 3;

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

bool containsIgnoreCase(const char* haystack, const char* needle) {
  if (haystack == nullptr || needle == nullptr) return false;
  const std::size_t hn = std::strlen(haystack);
  const std::size_t nn = std::strlen(needle);
  if (nn == 0) return true;
  if (nn > hn) return false;

  for (std::size_t i = 0; i + nn <= hn; ++i) {
    std::size_t j = 0;
    while (j < nn && lowerAscii(haystack[i + j]) == lowerAscii(needle[j])) ++j;
    if (j == nn) return true;
  }
  return false;
}

void setError(char* buf, std::size_t cap, const char* fmt, const char* detail) {
  if (cap == 0) return;
  const int n = std::snprintf(buf, cap, fmt, detail == nullptr ? "" : detail);
  if (n < 0) buf[0] = '\0';
}

// The two-placeholder form, for rules where both the key and the offending value
// belong in the message. A filter that rejects `proto=nonsense` without saying which
// token was wrong leaves the operator guessing at the comma placement.
void setError2(char* buf, std::size_t cap, const char* fmt, const char* key,
               const char* value) {
  if (cap == 0) return;
  const int n = std::snprintf(buf, cap, fmt, key == nullptr ? "" : key,
                              value == nullptr ? "" : value);
  if (n < 0) buf[0] = '\0';
}

void setErrorLiteral(char* buf, std::size_t cap, const char* text) {
  if (cap == 0) return;
  std::size_t i = 0;
  for (; i + 1 < cap && text[i] != '\0'; ++i) buf[i] = text[i];
  buf[i] = '\0';
}

// The token list a rule's value is walked as.
//
// `applyRule` receives a pointer into a mutable copy of the spec, so the text it
// points at really is writable; this exists only to make that fact explicit at the
// one call site that needs it, rather than scattering const_casts.
char* mutableText(const char* s) {
  return const_cast<char*>(s);
}

// A comma tokenizer that does not depend on strtok_r.
//
// strtok_r is POSIX and absent on MSVC, which is one of the three platforms the gate
// runs on. Rather than #ifdef around a two-line loop, the loop is written out.
class CommaList {
 public:
  explicit CommaList(char* text) : text_(text) {}

  // Returns the next token, or nullptr when done. The token lives in the buffer the
  // list was constructed over, so it is only valid until the next call.
  char* next() {
    if (done_) return nullptr;

    if (cursor_ == nullptr) {
      cursor_ = text_;
    } else if (pendingSkip_ && *cursor_ == ',') {
      // Step over the delimiter the previous token left behind -- and only that.
      // Advancing unconditionally ate the first character of every token after the
      // first, which turned "proto=meshcore,meshtastic" into an unknown key
      // "eshtastic".
      ++cursor_;
    }
    pendingSkip_ = false;

    if (*cursor_ == '\0') {
      done_ = true;
      return nullptr;
    }

    // Step over whitespace at the start of every token, not just the delimiter.
    //
    // Only the delimiter used to be skipped, so a rule list written the way a person
    // writes one -- "untraceable=true, rssi<-90" -- failed with "unknown filter key:
    //  rssi", leading space and all. An operator who has to remember not to put a space
    // after a comma is an operator who will eventually forget.
    while (*cursor_ == ' ' || *cursor_ == '\t') ++cursor_;
    if (*cursor_ == '\0') {
      done_ = true;
      return nullptr;
    }

    char* start = cursor_;
    while (*cursor_ != '\0' && *cursor_ != ',') ++cursor_;
    if (*cursor_ == ',') {
      *cursor_ = '\0';
      ++cursor_;
      pendingSkip_ = true;
    } else {
      done_ = true;
    }
    return start;
  }

 private:
  char* text_;
  char* cursor_ = nullptr;
  bool done_ = false;
  bool pendingSkip_ = false;
};

bool parseBool(const char* v, bool* out) {
  if (equalsIgnoreCase(v, "true") || equalsIgnoreCase(v, "yes") || equalsIgnoreCase(v, "1") ||
      equalsIgnoreCase(v, "on")) {
    *out = true;
    return true;
  }
  if (equalsIgnoreCase(v, "false") || equalsIgnoreCase(v, "no") || equalsIgnoreCase(v, "0") ||
      equalsIgnoreCase(v, "off")) {
    *out = false;
    return true;
  }
  return false;
}

bool parseHex64(const char* v, std::uint64_t* out) {
  const std::size_t n = std::strlen(v);
  if (n == 0 || n > 16) return false;
  std::uint64_t h = 0;
  for (std::size_t i = 0; i < n; ++i) {
    const char c = v[i];
    std::uint8_t d;
    if (c >= '0' && c <= '9') {
      d = static_cast<std::uint8_t>(c - '0');
    } else if (c >= 'a' && c <= 'f') {
      d = static_cast<std::uint8_t>(c - 'a' + 10);
    } else if (c >= 'A' && c <= 'F') {
      d = static_cast<std::uint8_t>(c - 'A' + 10);
    } else {
      return false;
    }
    h = (h << 4) | static_cast<std::uint64_t>(d);
  }
  *out = h;
  return true;
}

bool parseInt(const char* v, long* out) {
  char* end = nullptr;
  const long n = std::strtol(v, &end, 10);
  if (end == v || (end != nullptr && *end != '\0')) return false;
  *out = n;
  return true;
}

// One comma-separated rule. Split in place so no allocation happens per rule.
bool applyRule(FilterSpec* f, char* rule, char* error, std::size_t errorCap) {
  // The first operator character in the rule, and the value that follows it. Keeping
  // the operator's *position* is what makes the key usable: the rule token is one
  // string, so "untraceable=true" has to have a NUL written at the '=' before the key
  // can be compared against anything. Trimming a computed length is not enough --
  // that terminates at the end of the token, which is where it already is.
  char* op = std::strpbrk(rule, "=<>");
  char* key = rule;
  const char* value = "";
  bool isLower = false;
  bool isUpper = false;
  bool isEqual = false;

  if (op == nullptr) {
    // A bare token: treat it as "this is on". `untraceable` reads naturally, and a
    // bare word cannot narrow anything by accident, so there is no reason to reject
    // it.
    value = "";
  } else if (op[0] == '=') {
    value = op + 1;
    isEqual = true;
  } else if (op[0] == '<') {
    isLower = true;
    value = op + 1;
    // "rssi>=-90" is one rule, not "rssi>=" followed by a value starting with "=".
    if (value[0] == '=') {
      value += 1;
      isEqual = true;
    }
  } else {
    isUpper = true;
    value = op + 1;
    if (value[0] == '=') {
      value += 1;
      isEqual = true;
    }
  }

  // Terminate the key at the operator, then trim any whitespace that was left in
  // front of it.
  if (op != nullptr) *op = '\0';
  std::size_t klen = std::strlen(key);
  while (klen > 0 && (key[klen - 1] == ' ' || key[klen - 1] == '\t')) {
    key[--klen] = '\0';
  }

  if (klen == 0) {
    setError(error, errorCap, "empty rule in: %s", rule);
    return false;
  }

  // --- inclusion/exclusion switches ---
  //
  // Checked before the comparison operators below, and that ordering is load-bearing:
  // `untraceable=true` contains an '=', so the operator block would otherwise claim
  // it, fall through every branch, and reject the whole spec with "unknown filter
  // key". A boolean switch has to be recognised as one.
  if (equalsIgnoreCase(key, "untraceable") || equalsIgnoreCase(key, "anomaly")) {
    bool on = true;
    if (value[0] != '\0' && !parseBool(value, &on)) {
      setError2(error, errorCap, "%s wants true or false, got: %s", key, value);
      return false;
    }
    if (equalsIgnoreCase(key, "untraceable")) {
      f->onlyUntraceable = on;
    } else {
      f->onlyAnomalies = on;
    }
    return true;
  }

  if (equalsIgnoreCase(key, "noise") || equalsIgnoreCase(key, "corrupt")) {
    bool on = true;
    if (value[0] != '\0' && !parseBool(value, &on)) {
      setError2(error, errorCap, "%s wants true or false, got: %s", key, value);
      return false;
    }
    if (equalsIgnoreCase(key, "noise")) {
      f->includeNoise = on;
    } else {
      f->includeCorrupt = on;
    }
    return true;
  }
  // --- comparison operators ---
  if (isLower || isUpper || isEqual) {
    if (equalsIgnoreCase(key, "rssi")) {
      long v = 0;
      if (!parseInt(value, &v)) {
        setError(error, errorCap, "rssi wants a number in dBm, got: %s", value);
        return false;
      }
      if (v < -128 || v > 127) {
        setError(error, errorCap, "rssi out of range: %s", value);
        return false;
      }
      f->hasRssi = true;
      f->rssiIsLowerBound = isLower && !isEqual;
      // The equality form is inclusive; `rssi>77` and `rssi<77` are not. Treating
      // `rssi=77` as an upper bound rejected the very value it named.
      f->rssiIsExact = isEqual && !isLower && !isUpper;
      f->rssi = static_cast<std::int16_t>(v);
      return true;
    }

    if (equalsIgnoreCase(key, "repeat")) {
      long v = 0;
      if (!parseInt(value, &v) || v < 0) {
        setError(error, errorCap, "repeat wants a count, got: %s", value);
        return false;
      }
      f->hasRepeat = true;
      f->repeatMin = static_cast<std::uint32_t>(v);
      return true;
    }

    if (equalsIgnoreCase(key, "fp")) {
      std::uint64_t h = 0;
      if (!parseHex64(value, &h)) {
        setError(error, errorCap, "fp wants up to 16 hex digits, got: %s", value);
        return false;
      }
      f->hasFingerprint = true;
      f->fingerprint = h;
      return true;
    }

    if (equalsIgnoreCase(key, "text")) {
      if (value[0] == '\0') {
        setError(error, errorCap, "text wants something to look for", nullptr);
        return false;
      }
      std::size_t i = 0;
      for (; i + 1 < sizeof(f->text) && value[i] != '\0'; ++i) f->text[i] = value[i];
      f->text[i] = '\0';
      f->hasText = true;
      return true;
    }
  }

  // --- set-valued rules ---
  if (equalsIgnoreCase(key, "proto")) {
    if (value[0] == '\0') {
      setError(error, errorCap, "proto wants at least one protocol", nullptr);
      return false;
    }
    f->anyProtocol = true;
    CommaList list(mutableText(value));
    char* tok = list.next();
    while (tok != nullptr) {
      Protocol p;
      if (!parseProtocol(tok, &p)) {
        setError(error, errorCap, "unknown protocol: %s", tok);
        return false;
      }
      f->protocol[static_cast<std::size_t>(p)] = true;
      tok = list.next();
    }
    return true;
  }

  if (equalsIgnoreCase(key, "net")) {
    if (value[0] == '\0') {
      setError(error, errorCap, "net wants at least one network", nullptr);
      return false;
    }
    f->anyNetwork = true;
    CommaList list(mutableText(value));
    char* tok = list.next();
    while (tok != nullptr) {
      Network n;
      if (!parseNetwork(tok, &n)) {
        setError(error, errorCap, "unknown network: %s", tok);
        return false;
      }
      f->network[static_cast<std::size_t>(n)] = true;
      tok = list.next();
    }
    return true;
  }

  if (equalsIgnoreCase(key, "attrib")) {
    if (value[0] == '\0') {
      setError(error, errorCap, "attrib wants attributed, partial or unattributed", nullptr);
      return false;
    }
    f->anyAttribution = true;
    CommaList list(mutableText(value));
    char* tok = list.next();
    while (tok != nullptr) {
      if (equalsIgnoreCase(tok, "attributed") || equalsIgnoreCase(tok, "full")) {
        f->attribution[static_cast<std::size_t>(Attribution::Attributed)] = true;
      } else if (equalsIgnoreCase(tok, "partial")) {
        f->attribution[static_cast<std::size_t>(Attribution::Partial)] = true;
      } else if (equalsIgnoreCase(tok, "unattributed") || equalsIgnoreCase(tok, "unknown")) {
        f->attribution[static_cast<std::size_t>(Attribution::Unattributed)] = true;
      } else {
        setError(error, errorCap, "unknown attribution: %s", tok);
        return false;
      }
      tok = list.next();
    }
    return true;
  }

  setError(error, errorCap, "unknown filter key: %s", key);
  return false;
}

}  // namespace

FilterSpec passAll() { return FilterSpec{}; }

bool parseFilter(const char* spec, FilterSpec* out, char* error, std::size_t errorCap) {
  if (out == nullptr) {
    setError(error, errorCap, "no destination given for the filter", nullptr);
    return false;
  }
  if (error != nullptr && errorCap > 0) error[0] = '\0';

  *out = passAll();
  if (spec == nullptr) return true;

  // The working copy is what gets tokenised. Bounded so a pathological spec
  // cannot be used to smash the stack; a spec longer than this is not a spec, it
  // is a mistake, and saying so is better than truncating it silently.
  constexpr std::size_t kMaxSpecBytes = 192;
  char work[kMaxSpecBytes];
  const std::size_t n = std::strlen(spec);
  if (n >= sizeof(work)) {
    setErrorLiteral(error, errorCap, "filter specification is too long; keep it under 192 bytes");
    return false;
  }
  std::memcpy(work, spec, n + 1);

  CommaList list(work);
  bool any = false;

  // Rules are comma-separated, and so are the values inside `proto=` and `net=`.
  // Those two uses collide, and the resolution is a continuation rule: a token with
  // no operator in it cannot start a rule, because every rule names a key, so it is
  // appended to the one before it. `proto=meshcore,meshtastic` is therefore one rule
  // with two values, `untraceable=true,rssi<-90` is two rules, and
  // `proto=mc,proto=mt` is two rules that both set the same key -- the second wins,
  // which is the ordinary reading of a repeated option.
  std::string pending;
  char* rule = list.next();
  while (rule != nullptr) {
    if (std::strpbrk(rule, "=<>") == nullptr && !pending.empty()) {
      pending += ",";
      pending += rule;
      rule = list.next();
      continue;
    }

    if (!pending.empty()) {
      if (!applyRule(out, &pending[0], error, errorCap)) return false;
      any = true;
      pending.clear();
    }

    pending = rule;
    rule = list.next();
  }
  if (!pending.empty()) {
    if (!applyRule(out, &pending[0], error, errorCap)) return false;
    any = true;
  }

  out->enabled = any;
  return true;
}

bool filterMatches(const FilterSpec& f, const Record& r) {
  if (!f.enabled) return true;

  if (r.noise && !f.includeNoise) return false;
  if (r.corrupt && !f.includeCorrupt) return false;

  if (f.onlyUntraceable && !isUntraceable(r.provenance.reason)) return false;
  if (f.onlyAnomalies && !isAnomaly(r.provenance.reason)) return false;

  if (f.anyProtocol && !f.protocol[static_cast<std::size_t>(r.protocol)]) return false;

  if (f.anyNetwork && !f.network[static_cast<std::size_t>(r.verdict.network)]) return false;

  if (f.anyAttribution &&
      !f.attribution[static_cast<std::size_t>(r.provenance.attribution)]) {
    return false;
  }

  if (f.hasRssi) {
    if (f.rssiIsExact) {
      if (r.link.rssiDbm != f.rssi) return false;
    } else if (f.rssiIsLowerBound) {
      if (r.link.rssiDbm >= f.rssi) return false;
    } else {
      if (r.link.rssiDbm <= f.rssi) return false;
    }
  }

  if (f.hasRepeat && r.repeatCount < f.repeatMin) return false;

  if (f.hasFingerprint && r.fingerprint != f.fingerprint) return false;

  if (f.hasText) {
    // Matched against every decoded value, not just one designated "text" field.
    // An operator filtering for a node name should find it whether it arrived in
    // an advert's name or in a message body, and making them specify which field
    // would be a rule nobody remembers.
    bool hit = false;
    for (std::size_t i = 0; i < r.decoded.count && !hit; ++i) {
      if (containsIgnoreCase(r.decoded.fields[i].value, f.text)) hit = true;
    }
    if (!hit) return false;
  }

  return true;
}

std::string describeFilter(const FilterSpec& f) {
  if (!f.enabled) return "filter: off (everything shown)";

  std::string s = "filter:";
  if (f.onlyUntraceable) s += " untraceable";
  if (f.onlyAnomalies) s += " anomaly";
  if (f.anyProtocol) {
    s += " proto=";
    bool first = true;
    for (std::size_t i = 0; i < kProtocolCount; ++i) {
      if (!f.protocol[i]) continue;
      if (!first) s += ",";
      s += protocolTag(static_cast<Protocol>(i));
      first = false;
    }
  }
  if (f.anyNetwork) {
    s += " net=";
    bool first = true;
    for (std::size_t i = 0; i < kNetworkCount; ++i) {
      if (!f.network[i]) continue;
      if (!first) s += ",";
      const NetworkInfo* info = networkInfo(static_cast<Network>(i));
      s += (info != nullptr) ? info->community : "?";
      first = false;
    }
  }
  if (f.anyAttribution) {
    s += " attrib=";
    bool first = true;
    static const char* kNames[kAttributionCount] = {"attributed", "partial", "unattributed"};
    for (std::size_t i = 0; i < kAttributionCount; ++i) {
      if (!f.attribution[i]) continue;
      if (!first) s += ",";
      s += kNames[i];
      first = false;
    }
  }
  if (f.hasRssi) {
    char buf[24];
    const int w = std::snprintf(buf, sizeof(buf), " rssi%s%d",
                                f.rssiIsExact ? "=" : (f.rssiIsLowerBound ? "<" : ">"),
                                static_cast<int>(f.rssi));
    if (w > 0) s.append(buf, static_cast<std::size_t>(w));
  }
  if (f.hasRepeat) {
    char buf[24];
    const int w = std::snprintf(buf, sizeof(buf), " repeat>=%u",
                                static_cast<unsigned>(f.repeatMin));
    if (w > 0) s.append(buf, static_cast<std::size_t>(w));
  }
  if (f.hasFingerprint) s += " fp=" + toHex64(f.fingerprint);
  if (f.hasText) {
    s += " text=";
    s += f.text;
  }
  if (!f.includeNoise) s += " noise=off";
  if (!f.includeCorrupt) s += " corrupt=off";
  return s;
}

std::string serialiseFilter(const FilterSpec& f) {
  if (!f.enabled) return std::string();

  // Built as a comma-separated spec rather than derived from describeFilter().
  //
  // describeFilter() is for humans and separates rules with spaces, which is right
  // for reading and wrong for re-parsing -- parseFilter() splits on commas, so the
  // human form is not a valid spec. Emitting the human form and calling it a
  // round-trip was the bug this replaced: `serialiseFilter` fed back into
  // `parseFilter` produced one nonsense rule and a parse failure.
  std::string s;

  if (f.onlyUntraceable) s += "untraceable=true";
  if (f.onlyAnomalies) {
    if (!s.empty()) s += ",";
    s += "anomaly=true";
  }

  if (f.anyProtocol) {
    if (!s.empty()) s += ",";
    s += "proto=";
    bool first = true;
    for (std::size_t i = 0; i < kProtocolCount; ++i) {
      if (!f.protocol[i]) continue;
      if (!first) s += ",";
      s += protocolTag(static_cast<Protocol>(i));
      first = false;
    }
  }

  if (f.anyNetwork) {
    if (!s.empty()) s += ",";
    s += "net=";
    bool first = true;
    for (std::size_t i = 0; i < kNetworkCount; ++i) {
      if (!f.network[i]) continue;
      if (!first) s += ",";
      const NetworkInfo* info = networkInfo(static_cast<Network>(i));
      s += (info != nullptr) ? info->community : "?";
      first = false;
    }
  }

  if (f.anyAttribution) {
    if (!s.empty()) s += ",";
    s += "attrib=";
    bool first = true;
    static const char* const kNames[kAttributionCount] = {"attributed", "partial",
                                                          "unattributed"};
    for (std::size_t i = 0; i < kAttributionCount; ++i) {
      if (!f.attribution[i]) continue;
      if (!first) s += ",";
      s += kNames[i];
      first = false;
    }
  }

  if (f.hasRssi) {
    if (!s.empty()) s += ",";
    char buf[24];
    const int w = std::snprintf(buf, sizeof(buf), "rssi%s%d",
                                f.rssiIsExact ? "=" : (f.rssiIsLowerBound ? "<" : ">"),
                                static_cast<int>(f.rssi));
    if (w > 0) s.append(buf, static_cast<std::size_t>(w));
  }
  if (f.hasRepeat) {
    if (!s.empty()) s += ",";
    char buf[24];
    const int w = std::snprintf(buf, sizeof(buf), "repeat>=%u", static_cast<unsigned>(f.repeatMin));
    if (w > 0) s.append(buf, static_cast<std::size_t>(w));
  }
  if (f.hasFingerprint) {
    if (!s.empty()) s += ",";
    s += "fp=" + toHex64(f.fingerprint);
  }
  if (f.hasText) {
    if (!s.empty()) s += ",";
    s += "text=";
    s += f.text;
  }
  if (!f.includeNoise) {
    if (!s.empty()) s += ",";
    s += "noise=false";
  }
  if (!f.includeCorrupt) {
    if (!s.empty()) s += ",";
    s += "corrupt=false";
  }
  return s;
}

}  // namespace sniff
