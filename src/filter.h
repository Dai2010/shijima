#pragma once
#include <cstddef>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace shijima {

// 通配符规则（fnmatch 语义）。allow 规则一旦存在，则默认拒绝，
// deny 规则始终优先。
class Filter {
 public:
  void add(bool allow, const std::string& pattern);
  bool remove_rule(bool allow, const std::string& pattern);
  bool load_file(const std::string& path, std::string& err);
  bool save(const std::string& path, std::string& err) const;
  void set_store_path(const std::string& path) { store_path_ = path; }
  const std::string& store_path() const { return store_path_; }
  bool allowed(const std::string& host) const;
  bool has_allow() const;
  size_t size() const;
  std::vector<std::pair<bool, std::string>> snapshot() const;
  void clear();

 private:
  void persist_locked();
  mutable std::mutex mtx_;
  std::vector<std::pair<bool, std::string>> rules_;
  bool has_allow_ = false;
  std::string store_path_;
};

std::vector<std::string> split_patterns(const std::string& s);

}  // namespace shijima
