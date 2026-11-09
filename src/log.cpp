#include "log.h"

#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "util.h"

namespace shijima {
namespace {

const char* kVersion = "0.1.0";

std::string one_line(const std::string& s, size_t max) {
  std::string out;
  out.reserve(std::min(s.size(), max));
  for (char c : s) {
    if (out.size() >= max) {
      out += "…";
      break;
    }
    out += (c == '\n' || c == '\r') ? ' ' : c;
  }
  return out;
}

bool is_binary_type(const std::string& ct) {
  std::string t = to_lower(ct);
  if (t.empty()) return false;
  return t.rfind("image/", 0) == 0 || t.rfind("audio/", 0) == 0 ||
         t.rfind("video/", 0) == 0 || t.rfind("font/", 0) == 0 ||
         t.find("octet-stream") != std::string::npos ||
         t.find("protobuf") != std::string::npos ||
         t.find("zip") != std::string::npos;
}

}  // namespace

bool Logger::init(const LogOptions& opt, std::string& err) {
  opt_ = opt;
  if (!opt_.file) return true;
  if (opt_.path.empty()) {
    err = "未指定抓包文件路径";
    return false;
  }
  std::string backup = opt_.path + ".1";
  if (file_exists(opt_.path)) {
    unlink(backup.c_str());
    if (rename(opt_.path.c_str(), backup.c_str()) != 0) {
      // 覆盖失败也继续，后面 fopen("w") 会截断
    }
  }
  f_ = fopen(opt_.path.c_str(), "w");
  if (!f_) {
    err = "无法写入 " + opt_.path + ": " + strerror(errno);
    return false;
  }
  setvbuf(f_, nullptr, _IOFBF, 64 * 1024);
  write_header();
  return true;
}

void Logger::write_header() {
  first_ = true;
  if (opt_.format == "json") {
    fputs("[\n", f_);
    bytes_ += 2;
  } else if (opt_.format == "xml") {
    int n = fprintf(f_, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<shijima version=\"%s\">\n",
                    kVersion);
    if (n > 0) bytes_ += (uint64_t)n;
  }
}

void Logger::write_footer() {
  if (!f_) return;
  if (opt_.format == "json") {
    fputs("\n]\n", f_);
    bytes_ += 3;
  } else if (opt_.format == "xml") {
    fputs("</shijima>\n", f_);
    bytes_ += 11;
  }
}

bool Logger::rotate() {
  if (!f_) return false;
  write_footer();
  fclose(f_);
  f_ = nullptr;
  std::string backup = opt_.path + ".1";
  unlink(backup.c_str());
  rename(opt_.path.c_str(), backup.c_str());
  f_ = fopen(opt_.path.c_str(), "w");
  if (!f_) return false;
  setvbuf(f_, nullptr, _IOFBF, 64 * 1024);
  bytes_ = 0;
  write_header();
  return true;
}

void Logger::emit(const Record& r) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (opt_.console) console_line(r);
  if (sink_) sink_(r);
  if (f_) {
    file_record(r);
    records_++;
    if (opt_.max_file_bytes > 0 && bytes_ > opt_.max_file_bytes) rotate();
  }
}

void Logger::flush() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (f_) fflush(f_);
  fflush(stdout);
}

void Logger::close() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!f_) return;
  write_footer();
  fflush(f_);
  fclose(f_);
  f_ = nullptr;
}

void Logger::console_line(const Record& r) {
  const bool c = opt_.color;
  const char* reset = c ? "\033[0m" : "";
  const char* dim = c ? "\033[2m" : "";
  const char* bold = c ? "\033[1m" : "";
  const char* cyan = c ? "\033[36m" : "";
  const char* green = c ? "\033[32m" : "";
  const char* yellow = c ? "\033[33m" : "";
  const char* red = c ? "\033[31m" : "";
  const char* magenta = c ? "\033[35m" : "";

  char ts[16] = "--:--:--.---";
  if (r.time.size() >= 23)
    snprintf(ts, sizeof ts, "%.12s", r.time.c_str() + 11);
  else
    snprintf(ts, sizeof ts, "%s", r.time.c_str());

  std::string line;
  line += dim;
  line += ts;
  line += reset;
  line += " ";
  line += dim;
  line += "#" + std::to_string(r.conn);
  line += reset;
  line += "  ";

  if (r.kind == "request") {
    line += cyan;
    line += "REQ";
    line += reset;
    line += "  ";
    line += bold;
    line += r.method;
    line += reset;
    line += "  ";
    line += r.scheme + "://" + r.host + r.target;
    line += dim;
    line += "  (";
    line += r.proto;
    if (!r.content_type.empty()) line += ", " + r.content_type;
    if (r.size > 0) line += ", " + fmt_size(r.size);
    line += ")";
    line += reset;
    if (!r.preview.empty()) {
      line += "  ";
      line += one_line(r.preview, 120);
    }
  } else if (r.kind == "response") {
    const char* sc = green;
    if (r.status >= 300 && r.status < 400)
      sc = yellow;
    else if (r.status >= 400)
      sc = red;
    line += sc;
    line += "RES";
    line += reset;
    line += "  ";
    line += sc;
    line += std::to_string(r.status);
    line += reset;
    line += "  ";
    line += r.content_type.empty() ? "-" : r.content_type;
    line += "  ";
    line += fmt_size(r.size);
    line += "  ";
    line += fmt_duration(r.duration_ms);
    if (!r.preview.empty()) {
      line += "  ";
      if (r.preview_binary)
        line += dim + std::string("[binary] ") + reset + r.preview;
      else
        line += one_line(r.preview, 120);
    }
  } else if (r.kind == "connection") {
    line += magenta;
    line += "CON";
    line += reset;
    line += "  ";
    line += r.note;
    line += "  ";
    line += dim;
    line += r.host;
    if (r.port) line += ":" + std::to_string(r.port);
    if (!r.proto.empty()) line += "  " + r.proto;
    line += reset;
  } else if (r.kind == "tunnel") {
    line += magenta;
    line += "TUN";
    line += reset;
    line += "  ";
    line += r.host + ":" + std::to_string(r.port);
    line += "  ";
    line += dim;
    line += r.note;
    line += reset;
  } else if (r.kind == "error") {
    line += red;
    line += "ERR";
    line += reset;
    line += "  ";
    line += r.note;
    if (!r.host.empty()) line += std::string("  ") + dim + r.host + reset;
  } else if (r.kind == "summary") {
    line += dim;
    line += r.note;
    line += reset;
  } else {
    line += r.kind + "  " + r.note;
  }
  fputs(line.c_str(), stdout);
  fputc('\n', stdout);
  fflush(stdout);
}

void Logger::file_record(const Record& r) {
  std::string out;
  if (opt_.format == "xml") {
    out += "  <record>\n";
    auto tag = [&](const char* k, const std::string& v) {
      out += "    <";
      out += k;
      out += ">";
      out += xml_escape(v);
      out += "</";
      out += k;
      out += ">\n";
    };
    tag("kind", r.kind);
    tag("conn", std::to_string(r.conn));
    tag("time", r.time);
    tag("src", r.src);
    tag("scheme", r.scheme);
    tag("host", r.host);
    tag("port", std::to_string(r.port));
    tag("proto", r.proto);
    tag("method", r.method);
    tag("target", r.target);
    tag("status", std::to_string(r.status));
    tag("content_type", r.content_type);
    tag("size", std::to_string(r.size));
    tag("duration_ms", std::to_string(r.duration_ms));
    tag("preview", r.preview);
    tag("preview_binary", r.preview_binary ? "true" : "false");
    tag("note", r.note);
    out += "  </record>\n";
  } else {
    std::string j = "{";
    auto str = [&](const char* k, const std::string& v) {
      j += '"';
      j += k;
      j += "\":\"";
      j += json_escape(v);
      j += "\",";
    };
    auto num = [&](const char* k, unsigned long long v) {
      j += '"';
      j += k;
      j += "\":";
      j += std::to_string(v);
      j += ",";
    };
    str("kind", r.kind);
    num("conn", r.conn);
    str("time", r.time);
    str("src", r.src);
    str("scheme", r.scheme);
    str("host", r.host);
    num("port", r.port);
    str("proto", r.proto);
    str("method", r.method);
    str("target", r.target);
    num("status", (unsigned long long)(r.status < 0 ? 0 : r.status));
    str("content_type", r.content_type);
    num("size", r.size);
    num("duration_ms", r.duration_ms);
    str("preview", r.preview);
    j += "\"preview_binary\":";
    j += r.preview_binary ? "true" : "false";
    j += ",";
    str("note", r.note);
    j.pop_back();  // trailing comma
    j += "}";
    if (opt_.format == "json") {
      if (!first_) {
        fputs(",\n", f_);
        bytes_ += 2;
      }
      first_ = false;
      out = "  " + j;
    } else {
      out = j;
    }
  }
  out += "\n";
  fwrite(out.data(), 1, out.size(), f_);
  bytes_ += out.size();
}

bool is_binary_content_type(const std::string& ct, const std::string& encoding) {
  if (!encoding.empty() && to_lower(encoding) != "identity") return true;
  return is_binary_type(ct);
}

}  // namespace shijima
