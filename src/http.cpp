#include "http.h"

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>

#include "util.h"

namespace shijima {

std::string HttpHeaders::get(const std::string& name) const {
  std::string want = to_lower(name);
  for (const auto& kv : items)
    if (kv.first == want) return kv.second;
  return std::string();
}

bool HttpHeaders::has(const std::string& name) const {
  std::string want = to_lower(name);
  for (const auto& kv : items)
    if (kv.first == want) return true;
  return false;
}

HttpParser::HttpParser(bool is_request, size_t header_limit, size_t preview_limit)
    : is_request_(is_request), header_limit_(header_limit), preview_limit_(preview_limit) {}

void HttpParser::feed(const char* data, size_t n) {
  size_t i = 0;
  while (i < n) {
    switch (phase_) {
      case Phase::Head: {
        head_.push_back(data[i++]);
        if (head_.size() >= 4 && head_[head_.size() - 4] == '\r' &&
            head_[head_.size() - 3] == '\n' && head_[head_.size() - 2] == '\r' &&
            head_[head_.size() - 1] == '\n') {
          if (!parse_head()) {
            broken_ = true;
            phase_ = Phase::Passthrough;
          }
        } else if (head_.size() > header_limit_) {
          broken_ = true;
          phase_ = Phase::Passthrough;
        }
        break;
      }
      case Phase::BodyFixed: {
        size_t take = (size_t)std::min<uint64_t>(remain_, n - i);
        body(data + i, take);
        i += take;
        remain_ -= take;
        if (remain_ == 0) complete_now();
        break;
      }
      case Phase::TillClose: {
        body(data + i, n - i);
        i = n;
        break;
      }
      case Phase::ChunkSize: {
        char ch = data[i++];
        if (ch == '\n') {
          std::string s = line_;
          line_.clear();
          while (!s.empty() && (s.back() == '\r' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
          size_t semi = s.find(';');
          if (semi != std::string::npos) s.resize(semi);
          char* end = nullptr;
          unsigned long long v = s.empty() ? 0 : strtoull(s.c_str(), &end, 16);
          if (s.empty() || end == s.c_str()) {
            broken_ = true;
            phase_ = Phase::Passthrough;
            break;
          }
          if (v == 0) {
            phase_ = Phase::Trailer;
          } else {
            chunk_remain_ = v;
            phase_ = Phase::ChunkData;
          }
        } else {
          line_.push_back(ch);
          if (line_.size() > 512) {
            broken_ = true;
            phase_ = Phase::Passthrough;
          }
        }
        break;
      }
      case Phase::ChunkData: {
        size_t take = (size_t)std::min<uint64_t>(chunk_remain_, n - i);
        body(data + i, take);
        i += take;
        chunk_remain_ -= take;
        if (chunk_remain_ == 0) phase_ = Phase::ChunkCrlf;
        break;
      }
      case Phase::ChunkCrlf: {
        if (data[i++] == '\n') phase_ = Phase::ChunkSize;
        break;
      }
      case Phase::Trailer: {
        char ch = data[i++];
        if (ch == '\n') {
          if (line_.empty() || line_ == "\r")
            complete_now();
          else
            line_.clear();
        } else {
          line_.push_back(ch);
          if (line_.size() > 1024) {
            broken_ = true;
            phase_ = Phase::Passthrough;
          }
        }
        break;
      }
      case Phase::Passthrough:
        i = n;
        break;
    }
  }
}

bool HttpParser::parse_head() {
  std::vector<std::string> lines;
  size_t pos = 0;
  while (pos < head_.size()) {
    size_t e = head_.find("\r\n", pos);
    if (e == std::string::npos) {
      lines.push_back(head_.substr(pos));
      break;
    }
    lines.push_back(head_.substr(pos, e - pos));
    pos = e + 2;
  }
  if (lines.empty() || lines[0].empty()) return false;

  msg_.is_request = is_request_;
  if (is_request_) {
    const std::string& l = lines[0];
    size_t sp1 = l.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = l.rfind(' ');
    if (sp2 == std::string::npos || sp2 <= sp1) return false;
    msg_.method = l.substr(0, sp1);
    msg_.target = l.substr(sp1 + 1, sp2 - sp1 - 1);
    msg_.version = l.substr(sp2 + 1);
  } else {
    const std::string& l = lines[0];
    size_t sp1 = l.find(' ');
    if (sp1 == std::string::npos) return false;
    size_t sp2 = l.find(' ', sp1 + 1);
    msg_.version = l.substr(0, sp1);
    std::string code =
        l.substr(sp1 + 1, (sp2 == std::string::npos ? l.size() : sp2) - sp1 - 1);
    msg_.status = atoi(code.c_str());
    if (msg_.status < 100 || msg_.status > 999) return false;
    if (sp2 != std::string::npos) msg_.reason = l.substr(sp2 + 1);
  }

  for (size_t i = 1; i < lines.size(); ++i) {
    if (lines[i].empty()) continue;
    size_t c = lines[i].find(':');
    if (c == std::string::npos) continue;
    std::string name = to_lower(trim_copy(lines[i].substr(0, c)));
    std::string value = trim_copy(lines[i].substr(c + 1));
    if (name.empty()) continue;
    msg_.headers.items.emplace_back(std::move(name), std::move(value));
  }
  msg_.raw_head = head_;

  std::string te = to_lower(msg_.headers.get("transfer-encoding"));
  bool chunked = te.find("chunked") != std::string::npos;
  std::string cl_str = msg_.headers.get("content-length");
  bool has_cl = false;
  uint64_t cl = 0;
  if (!cl_str.empty()) {
    char* end = nullptr;
    errno = 0;
    unsigned long long v = strtoull(cl_str.c_str(), &end, 10);
    if (end != cl_str.c_str() && errno == 0) {
      cl = v;
      has_cl = true;
    }
  }
  msg_.chunked = chunked;

  if (is_request_) {
    if (chunked) {
      phase_ = Phase::ChunkSize;
    } else if (has_cl && cl > 0) {
      phase_ = Phase::BodyFixed;
      remain_ = cl;
    } else {
      complete_now();
    }
  } else {
    bool no_body = no_body_hint_ || msg_.status == 204 || msg_.status == 304 ||
                   (msg_.status >= 100 && msg_.status < 200 && msg_.status != 101);
    if (no_body) {
      complete_now();
    } else if (chunked) {
      phase_ = Phase::ChunkSize;
    } else if (has_cl) {
      if (cl == 0) {
        complete_now();
      } else {
        phase_ = Phase::BodyFixed;
        remain_ = cl;
      }
    } else {
      phase_ = Phase::TillClose;
      msg_.close_delimited = true;
    }
  }
  return true;
}

void HttpParser::body(const char* p, size_t n) {
  if (n == 0) return;
  msg_.body_size += n;
  if (msg_.body_preview.size() < preview_limit_) {
    size_t take = std::min(n, preview_limit_ - msg_.body_preview.size());
    msg_.body_preview.append(p, take);
    if (take < n) msg_.preview_truncated = true;
  } else {
    msg_.preview_truncated = true;
  }
  if (bcb_) bcb_(msg_, p, n);
}

void HttpParser::complete_now() {
  msg_.complete = true;
  if (dcb_) dcb_(msg_);
  msg_ = HttpMessage{};
  head_.clear();
  line_.clear();
  remain_ = 0;
  chunk_remain_ = 0;
  phase_ = Phase::Head;
}

void HttpParser::finish() {
  if (phase_ == Phase::Head || phase_ == Phase::Passthrough) return;
  complete_now();
}

void HttpParser::stop() {
  broken_ = true;
  phase_ = Phase::Passthrough;
}

}  // namespace shijima
