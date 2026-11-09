#include "filter.h"

#include <fnmatch.h>

#include <fstream>
#include <vector>

#include "util.h"

namespace shijima {

std::vector<std::string> split_patterns(const std::string& s) {
  std::vector<std::string> out;
  size_t start = 0;
  while (start <= s.size()) {
    size_t comma = s.find(',', start);
    std::string item =
        trim_copy(s.substr(start, comma == std::string::npos ? std::string::npos : comma - start));
    if (!item.empty()) out.push_back(item);
    if (comma == std::string::npos) break;
    start = comma + 1;
  }
  return out;
}

namespace {

std::string strip_quotes(std::string s) {
  if (s.size() >= 2 && s.front() == '"' && s.back() == '"') return s.substr(1, s.size() - 2);
  if (s.size() >= 2 && s.front() == '\'' && s.back() == '\'') return s.substr(1, s.size() - 2);
  return s;
}

std::string quote_yaml(const std::string& s) {
  std::string out = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') out += '\\';
    out += c;
  }
  out += '"';
  return out;
}

}  // namespace

void Filter::add(bool allow, const std::string& pattern) {
  std::string p = to_lower(trim_copy(pattern));
  if (p.empty()) return;
  std::lock_guard<std::mutex> lock(mtx_);
  rules_.emplace_back(allow, p);
  if (allow) has_allow_ = true;
  persist_locked();
}

bool Filter::remove_rule(bool allow, const std::string& pattern) {
  std::string p = to_lower(trim_copy(pattern));
  std::lock_guard<std::mutex> lock(mtx_);
  bool removed = false;
  for (auto it = rules_.begin(); it != rules_.end();) {
    if (it->first == allow && it->second == p) {
      it = rules_.erase(it);
      removed = true;
    } else {
      ++it;
    }
  }
  if (removed) {
    has_allow_ = false;
    for (const auto& kv : rules_)
      if (kv.first) has_allow_ = true;
    persist_locked();
  }
  return removed;
}

bool Filter::load_file(const std::string& path, std::string& err) {
  std::ifstream in(path);
  if (!in) {
    err = "无法读取规则文件: " + path;
    return false;
  }
  std::string line;
  bool allow_section = false;
  bool deny_section = false;
  while (std::getline(in, line)) {
    std::string s = trim_copy(line);
    if (s.empty() || s[0] == '#') continue;
    if (s == "allow:" || s == "allow") {
      allow_section = true;
      deny_section = false;
      continue;
    }
    if (s == "deny:" || s == "deny") {
      allow_section = false;
      deny_section = true;
      continue;
    }
    if (s.rfind("allow:", 0) == 0 && s.size() > 6) {
      add(true, trim_copy(s.substr(6)));
      continue;
    }
    if (s.rfind("deny:", 0) == 0 && s.size() > 5) {
      add(false, trim_copy(s.substr(5)));
      continue;
    }
    if (s.rfind("- ", 0) == 0 || s[0] == '-') {
      std::string item = trim_copy(s.substr(s.rfind("- ", 0) == 0 ? 2 : 1));
      if (!item.empty()) add(allow_section, strip_quotes(item));
      continue;
    }
    if (s.rfind("+ ", 0) == 0 || s[0] == '+') {
      std::string item = trim_copy(s.substr(s.rfind("+ ", 0) == 0 ? 2 : 1));
      if (!item.empty()) add(true, strip_quotes(item));
      continue;
    }
    if (s.rfind("allow ", 0) == 0) {
      add(true, strip_quotes(trim_copy(s.substr(6))));
      continue;
    }
    if (s.rfind("deny ", 0) == 0) {
      add(false, strip_quotes(trim_copy(s.substr(5))));
      continue;
    }
    // 裸通配符：按 deny 处理（兼容旧格式）
    (void)deny_section;
    add(false, strip_quotes(s));
  }
  return true;
}

void Filter::persist_locked() {
  if (store_path_.empty()) return;
  size_t slash = store_path_.rfind('/');
  if (slash != std::string::npos) ensure_dir(store_path_.substr(0, slash), 0700);
  std::ofstream out(store_path_, std::ios::trunc);
  if (!out) return;
  out << "# shijima 过滤规则（YAML）\n";
  out << "# deny 优先；只要存在 allow，则未匹配的主机默认拒绝。\n";
  out << "deny:\n";
  for (const auto& kv : rules_)
    if (!kv.first) out << "  - " << quote_yaml(kv.second) << "\n";
  out << "allow:\n";
  for (const auto& kv : rules_)
    if (kv.first) out << "  - " << quote_yaml(kv.second) << "\n";
}

bool Filter::save(const std::string& path, std::string& err) const {
  std::lock_guard<std::mutex> lock(mtx_);
  const_cast<Filter*>(this)->store_path_ = path;
  size_t slash = path.rfind('/');
  if (slash != std::string::npos) ensure_dir(path.substr(0, slash), 0700);
  std::ofstream out(path, std::ios::trunc);
  if (!out) {
    err = "无法写入规则文件: " + path;
    return false;
  }
  out << "# shijima 过滤规则（YAML）\n";
  out << "# deny 优先；只要存在 allow，则未匹配的主机默认拒绝。\n";
  out << "deny:\n";
  for (const auto& kv : rules_)
    if (!kv.first) out << "  - " << quote_yaml(kv.second) << "\n";
  out << "allow:\n";
  for (const auto& kv : rules_)
    if (kv.first) out << "  - " << quote_yaml(kv.second) << "\n";
  return true;
}

bool Filter::allowed(const std::string& host_raw) const {
  std::string host = to_lower(host_raw);
  while (!host.empty() && host.back() == '.') host.pop_back();
  std::lock_guard<std::mutex> lock(mtx_);
  for (const auto& kv : rules_)
    if (!kv.first && fnmatch(kv.second.c_str(), host.c_str(), 0) == 0) return false;
  if (!has_allow_) return true;
  for (const auto& kv : rules_)
    if (kv.first && fnmatch(kv.second.c_str(), host.c_str(), 0) == 0) return true;
  return false;
}

bool Filter::has_allow() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return has_allow_;
}

size_t Filter::size() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return rules_.size();
}

std::vector<std::pair<bool, std::string>> Filter::snapshot() const {
  std::lock_guard<std::mutex> lock(mtx_);
  return rules_;
}

void Filter::clear() {
  std::lock_guard<std::mutex> lock(mtx_);
  rules_.clear();
  has_allow_ = false;
  persist_locked();
}

}  // namespace shijima
