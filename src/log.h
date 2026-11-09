#pragma once
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <string>

namespace shijima {

struct Record {
  std::string kind;  // request | response | connection | tunnel | error | summary
  uint64_t conn = 0;
  std::string time;
  std::string src;
  std::string scheme;
  std::string host;
  int port = 0;
  std::string proto;
  std::string method;
  std::string target;
  int status = 0;
  std::string content_type;
  uint64_t size = 0;
  uint64_t duration_ms = 0;
  std::string preview;
  bool preview_binary = false;
  std::string note;
};

struct LogOptions {
  bool console = true;
  bool color = true;
  bool file = true;
  std::string path;
  std::string format = "json";  // json | jsonl | xml
  uint64_t max_file_bytes = 32ull * 1024 * 1024;
};

bool is_binary_content_type(const std::string& content_type, const std::string& encoding);

class Logger {
 public:
  bool init(const LogOptions& opt, std::string& err);
  void emit(const Record& r);
  void close();
  void flush();
  void set_sink(std::function<void(const Record&)> cb) { sink_ = std::move(cb); }
  bool file_open() const { return f_ != nullptr; }
  const std::string& path() const { return opt_.path; }
  uint64_t records() const { return records_; }
  uint64_t file_bytes() const { return bytes_; }

 private:
  void console_line(const Record& r);
  void file_record(const Record& r);
  bool rotate();
  void write_header();
  void write_footer();

  LogOptions opt_;
  std::FILE* f_ = nullptr;
  uint64_t records_ = 0;
  uint64_t bytes_ = 0;
  bool first_ = true;
  std::mutex mtx_;
  std::function<void(const Record&)> sink_;
};

}  // namespace shijima
