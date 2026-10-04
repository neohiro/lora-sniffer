// SPDX-License-Identifier: MIT

#include "sniffer/Jsonl.hpp"

#include <cstdarg>
#include <cstdio>

#include "sniffer/Fingerprint.hpp"

namespace sniff {
namespace {

// Appends with a hard cap. Every writer in this file goes through here so that
// no single field can be the one that overflows a buffer.
void append(char* out, std::size_t cap, std::size_t* len, const char* text) {
  if (*len >= cap) return;
  std::size_t i = 0;
  while (*len + i + 1 < cap && text[i] != '\0') {
    out[*len + i] = text[i];
    ++i;
  }
  *len += i;
}

void appendQuoted(char* out, std::size_t cap, std::size_t* len, const char* text) {
  append(out, cap, len, "\"");
  const std::size_t escaped = jsonEscape(text, out + *len, cap - *len);
  *len += escaped;
  append(out, cap, len, "\"");
}

void appendFmt(char* out, std::size_t cap, std::size_t* len, const char* fmt, ...) {
  if (*len >= cap) return;
  va_list ap;
  va_start(ap, fmt);
  const int n = std::vsnprintf(out + *len, cap - *len, fmt, ap);
  va_end(ap);
  if (n <= 0) return;
  const std::size_t wrote = static_cast<std::size_t>(n);
  *len += (wrote < cap - *len) ? wrote : cap - *len - 1;
}

}  // namespace

std::size_t jsonEscape(const char* in, char* out, std::size_t cap) {
  if (out == nullptr || cap == 0) return 0;
  std::size_t w = 0;

  if (in == nullptr) {
    if (cap > 1) out[0] = '\0';
    return 0;
  }

  for (std::size_t i = 0; in[i] != '\0'; ++i) {
    const unsigned char c = static_cast<unsigned char>(in[i]);
    char esc[8];
    std::size_t n = 0;

    switch (c) {
      case '"':
        esc[0] = '\\';
        esc[1] = '"';
        n = 2;
        break;
      case '\\':
        esc[0] = '\\';
        esc[1] = '\\';
        n = 2;
        break;
      case '\n':
        esc[0] = '\\';
        esc[1] = 'n';
        n = 2;
        break;
      case '\r':
        esc[0] = '\\';
        esc[1] = 'r';
        n = 2;
        break;
      case '\t':
        esc[0] = '\\';
        esc[1] = 't';
        n = 2;
        break;
      case '\b':
        esc[0] = '\\';
        esc[1] = 'b';
        n = 2;
        break;
      case '\f':
        esc[0] = '\\';
        esc[1] = 'f';
        n = 2;
        break;
      default:
        if (c < 0x20 || c == 0x7F) {
          // Control characters, including DEL, go out as \u00XX. A raw newline in
          // particular would end the line and the next record would parse as a
          // separate frame, which is precisely the forgery this file exists to
          // prevent.
          const int w2 = std::snprintf(esc, sizeof(esc), "\\u%04X", static_cast<unsigned>(c));
          n = (w2 > 0) ? static_cast<std::size_t>(w2) : 0;
        } else {
          esc[0] = static_cast<char>(c);
          n = 1;
        }
        break;
    }

    for (std::size_t k = 0; k < n; ++k) {
      if (w + 1 >= cap) {
        out[w] = '\0';
        return w;
      }
      out[w] = esc[k];
      ++w;
    }
  }

  out[w] = '\0';
  return w;
}

std::size_t toJsonLine(const Record& r, char* out, std::size_t cap) {
  if (out == nullptr || cap == 0) return 0;

  std::size_t len = 0;

  append(out, cap, &len, "{");

  // Format version first, always. Everything after it is a tool's problem.
  appendFmt(out, cap, &len, "\"v\":%u,", static_cast<unsigned>(kCaptureFormatVersion));

  appendFmt(out, cap, &len, "\"seq\":%u,", static_cast<unsigned>(r.seq));
  appendFmt(out, cap, &len, "\"t\":%u,", static_cast<unsigned>(r.timestampMs));

  // Identity of the frame.
  append(out, cap, &len, "\"proto\":");
  appendQuoted(out, cap, &len, protocolName(r.protocol));
  append(out, cap, &len, ",\"net\":");
  appendQuoted(out, cap, &len, r.verdict.name);
  append(out, cap, &len, ",\"community\":");
  appendQuoted(out, cap, &len, r.verdict.community);
  appendFmt(out, cap, &len, ",\"conf\":");
  appendQuoted(out, cap, &len, confidenceName(r.verdict.confidence));
  appendFmt(out, cap, &len, ",\"carrier_only\":%s", r.verdict.carrierOnly ? "true" : "false");

  // Attribution. `reason` is the field an operator filters on and
  // `untraceable` is the derived boolean the brief asks for, spelled out so a
  // host tool never has to keep its own copy of the reason table.
  append(out, cap, &len, ",\"attrib\":");
  appendQuoted(out, cap, &len, attributionName(r.provenance.attribution));
  append(out, cap, &len, ",\"decoder\":");
  appendQuoted(out, cap, &len, decoderIdName(r.provenance.decoder));
  append(out, cap, &len, ",\"reason\":");
  appendQuoted(out, cap, &len, reasonName(r.provenance.reason));
  appendFmt(out, cap, &len, ",\"untraceable\":%s", isUntraceable(r.provenance.reason) ? "true"
                                                                                      : "false");
  appendFmt(out, cap, &len, ",\"anomaly\":%s", isAnomaly(r.provenance.reason) ? "true" : "false");

  // Link evidence.
  appendFmt(out, cap, &len, ",\"rssi\":%d", static_cast<int>(r.link.rssiDbm));
  appendFmt(out, cap, &len, ",\"snr\":%.1f", static_cast<double>(r.link.snrDb));
  appendFmt(out, cap, &len, ",\"sync\":%u", static_cast<unsigned>(r.link.syncWord));
  appendFmt(out, cap, &len, ",\"sync_avail\":%s", r.link.syncWordAvailable ? "true" : "false");
  append(out, cap, &len, ",\"hdr\":");
  appendQuoted(out, cap, &len, checkName(r.link.headerCheck));
  append(out, cap, &len, ",\"crc\":");
  appendQuoted(out, cap, &len, checkName(r.link.crcCheck));
  append(out, cap, &len, ",\"why\":");
  appendQuoted(out, cap, &len, r.verdict.caveat);

  // Plan and repetition.
  append(out, cap, &len, ",\"plan\":");
  {
    const std::string key = planKey(r.listenPlan);
    appendQuoted(out, cap, &len, key.c_str());
  }
  appendFmt(out, cap, &len, ",\"fp\":");
  {
    const std::string fp = toHex64(r.fingerprint);
    appendQuoted(out, cap, &len, fp.c_str());
  }
  appendFmt(out, cap, &len, ",\"rep\":%u", static_cast<unsigned>(r.repeatCount));

  appendFmt(out, cap, &len, ",\"len\":%u", static_cast<unsigned>(r.length));
  appendFmt(out, cap, &len, ",\"corrupt\":%s", r.corrupt ? "true" : "false");
  appendFmt(out, cap, &len, ",\"noise\":%s", r.noise ? "true" : "false");
  appendFmt(out, cap, &len, ",\"filtered\":%s", r.filtered ? "true" : "false");

  // Decoded fields, as a nested object so a tool can iterate values without
  // knowing which protocol produced them.
  append(out, cap, &len, ",\"decoded\":{");
  for (std::size_t i = 0; i < r.decoded.count; ++i) {
    if (i > 0) append(out, cap, &len, ",");
    appendQuoted(out, cap, &len, r.decoded.fields[i].key);
    append(out, cap, &len, ":");
    appendQuoted(out, cap, &len, r.decoded.fields[i].value);
  }
  append(out, cap, &len, "}");

  // Raw bytes, so the capture can be re-decoded by a future firmware.
  append(out, cap, &len, ",\"data\":\"");
  {
    char hex[3];
    for (std::size_t i = 0; i < r.length && len + 3 < cap; ++i) {
      const int w = std::snprintf(hex, sizeof(hex), "%02x", static_cast<unsigned>(r.data[i]));
      if (w <= 0) break;
      append(out, cap, &len, hex);
    }
  }
  append(out, cap, &len, "\"}");

  append(out, cap, &len, "\n");

  // A line that hit the cap is a line a JSON parser will reject somewhere in the
  // middle, which is worse than no line at all. Refuse rather than truncate.
  if (len + 1 >= cap) return 0;
  out[len] = '\0';
  return len;
}

}  // namespace sniff
