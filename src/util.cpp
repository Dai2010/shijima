#include "util.h"

#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <random>

namespace shijima {

uint64_t mono_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

uint64_t rand_u64() {
  static thread_local std::mt19937_64 rng([] {
    std::random_device rd;
    return ((uint64_t)rd() << 32) ^ (uint64_t)rd() ^ (uint64_t)time(nullptr);
  }());
  return rng();
}

std::string now_iso_ms() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  struct tm tmv;
  localtime_r(&ts.tv_sec, &tmv);
  char base[64];
  size_t n = strftime(base, sizeof base, "%Y-%m-%dT%H:%M:%S", &tmv);
  long off = tmv.tm_gmtoff;
  int sign = off < 0 ? -1 : 1;
  long a = off < 0 ? -off : off;
  char out[80];
  snprintf(out, sizeof out, "%.*s.%03ld%c%02ld:%02ld", (int)n, base,
           ts.tv_nsec / 1000000L, sign < 0 ? '-' : '+', a / 3600, (a % 3600) / 60);
  return out;
}

std::string fmt_size(uint64_t n) {
  char b[64];
  if (n < 1024)
    snprintf(b, sizeof b, "%llu B", (unsigned long long)n);
  else if (n < 1024ull * 1024)
    snprintf(b, sizeof b, "%.1f KiB", n / 1024.0);
  else if (n < 1024ull * 1024 * 1024)
    snprintf(b, sizeof b, "%.1f MiB", n / 1048576.0);
  else
    snprintf(b, sizeof b, "%.2f GiB", n / 1073741824.0);
  return b;
}

std::string fmt_duration(uint64_t ms) {
  char b[64];
  if (ms < 1000)
    snprintf(b, sizeof b, "%llu ms", (unsigned long long)ms);
  else if (ms < 60000)
    snprintf(b, sizeof b, "%.1f s", ms / 1000.0);
  else
    snprintf(b, sizeof b, "%llum %llus", (unsigned long long)(ms / 60000),
             (unsigned long long)((ms / 1000) % 60));
  return b;
}

std::string to_lower(std::string s) {
  for (char& c : s)
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
  return s;
}

std::string trim_copy(const std::string& s) {
  size_t b = 0, e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) --e;
  return s.substr(b, e - b);
}

std::string json_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (c < 0x20) {
          char b[8];
          snprintf(b, sizeof b, "\\u%04x", c);
          out += b;
        } else {
          out += (char)c;
        }
    }
  }
  return out;
}

std::string xml_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&apos;"; break;
      default:
        if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') break;
        out += (char)c;
    }
  }
  return out;
}

std::string hexdump(const std::string& data, size_t max_bytes) {
  size_t n = data.size() < max_bytes ? data.size() : max_bytes;
  std::string out;
  out.reserve(n * 3 + 3);
  char b[4];
  for (size_t i = 0; i < n; ++i) {
    snprintf(b, sizeof b, "%02x", (unsigned char)data[i]);
    out += b;
    if (i + 1 < n) out += ' ';
  }
  if (data.size() > n) out += " ...";
  return out;
}

bool looks_binary(const std::string& data) {
  if (data.empty()) return false;
  size_t bad = 0;
  for (unsigned char c : data) {
    if (c == 0) return true;
    if (c < 0x09 || (c > 0x0d && c < 0x20)) ++bad;
  }
  return bad > 0 && bad * 100 / data.size() > 2;
}

std::string xdg_dir(const char* env_name, const char* fallback_rel) {
  const char* v = getenv(env_name);
  if (v && *v) return v;
  const char* home = getenv("HOME");
  std::string h = (home && *home) ? home : ".";
  if (fallback_rel && fallback_rel[0] == '/') return h + fallback_rel;
  return h + "/" + (fallback_rel ? fallback_rel : "");
}

bool ensure_dir(const std::string& path, int mode) {
  if (path.empty()) return false;
  for (size_t p = 1; p < path.size(); ++p) {
    if (path[p] != '/') continue;
    std::string d = path.substr(0, p);
    if (mkdir(d.c_str(), mode) != 0 && errno != EEXIST) return false;
  }
  if (mkdir(path.c_str(), mode) != 0 && errno != EEXIST) return false;
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool file_exists(const std::string& path) {
  struct stat st;
  return stat(path.c_str(), &st) == 0;
}

bool is_ip_literal(const std::string& host) {
  unsigned char buf[16];
  return inet_pton(AF_INET, host.c_str(), buf) == 1 ||
         inet_pton(AF_INET6, host.c_str(), buf) == 1;
}

}  // namespace shijima
