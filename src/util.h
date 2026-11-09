#pragma once
#include <cstddef>
#include <cstdint>
#include <string>

namespace shijima {

std::string now_iso_ms();
std::string fmt_size(uint64_t n);
std::string fmt_duration(uint64_t ms);
std::string to_lower(std::string s);
std::string trim_copy(const std::string& s);
std::string json_escape(const std::string& s);
std::string xml_escape(const std::string& s);
std::string hexdump(const std::string& data, size_t max_bytes);
bool looks_binary(const std::string& data);
std::string xdg_dir(const char* env_name, const char* fallback_rel);
bool ensure_dir(const std::string& path, int mode);
bool file_exists(const std::string& path);
bool is_ip_literal(const std::string& host);
uint64_t mono_ms();
uint64_t rand_u64();

}  // namespace shijima
