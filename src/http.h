#pragma once
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace shijima {

struct HttpHeaders {
  std::vector<std::pair<std::string, std::string>> items;
  std::string get(const std::string& name) const;
  bool has(const std::string& name) const;
};

struct HttpMessage {
  bool is_request = false;
  std::string method;
  std::string target;
  std::string version;
  int status = 0;
  std::string reason;
  HttpHeaders headers;
  std::string raw_head;
  uint64_t body_size = 0;
  std::string body_preview;
  bool preview_truncated = false;
  bool chunked = false;
  bool close_delimited = false;
  bool complete = false;
};

class HttpParser {
 public:
  using HeadersCb = std::function<void(HttpMessage&)>;
  using BodyCb = std::function<void(HttpMessage&, const char*, size_t)>;
  using DoneCb = std::function<void(HttpMessage&)>;

  HttpParser(bool is_request, size_t header_limit, size_t preview_limit);

  void on_headers(HeadersCb cb) { hcb_ = std::move(cb); }
  void on_body(BodyCb cb) { bcb_ = std::move(cb); }
  void on_done(DoneCb cb) { dcb_ = std::move(cb); }
  void set_no_body_hint(bool v) { no_body_hint_ = v; }

  void feed(const char* data, size_t n);
  void finish();
  void stop();
  bool broken() const { return broken_; }

 private:
  enum class Phase {
    Head,
    BodyFixed,
    ChunkSize,
    ChunkData,
    ChunkCrlf,
    Trailer,
    TillClose,
    Passthrough
  };

  bool parse_head();
  void body(const char* p, size_t n);
  void complete_now();

  bool is_request_;
  size_t header_limit_;
  size_t preview_limit_;
  Phase phase_ = Phase::Head;
  std::string head_;
  HttpMessage msg_;
  uint64_t remain_ = 0;
  uint64_t chunk_remain_ = 0;
  std::string line_;
  bool broken_ = false;
  bool no_body_hint_ = false;
  HeadersCb hcb_;
  BodyCb bcb_;
  DoneCb dcb_;
};

}  // namespace shijima
