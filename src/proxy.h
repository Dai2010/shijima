#pragma once
#include <openssl/ssl.h>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "filter.h"
#include "log.h"
#include "tls.h"

namespace shijima {

struct Options {
  std::string bind_addr = "127.0.0.1";
  uint16_t port = 8899;
  bool strict_port = false;
  bool mitm = true;
  bool insecure = false;
  bool tui = false;
  bool allow_remote = false;
  bool print_ca = false;
  size_t body_limit = 2048;
  int max_conn = 48;
  int idle_timeout = 300;
  LogOptions log;
  std::string ca_dir;
  Filter* filter = nullptr;
};

struct Stats {
  std::atomic<uint64_t> conns{0};
  std::atomic<uint64_t> mitm{0};
  std::atomic<uint64_t> tunnels{0};
  std::atomic<uint64_t> errors{0};
  std::atomic<uint64_t> requests{0};
  std::atomic<uint64_t> responses{0};
  std::atomic<uint64_t> blocked{0};
  std::atomic<uint64_t> up_bytes{0};
  std::atomic<uint64_t> down_bytes{0};
  std::atomic<uint64_t> start_ms{0};
  std::atomic<uint64_t> end_ms{0};
};

class Proxy {
 public:
  struct Conn;
  struct Side;

  Proxy(const Options& opt, Logger& log, CertStore* ca, Stats& stats);
  ~Proxy();

  bool init_tls(std::string& err);
  int run();
  void stop();
  void top_hosts(std::vector<std::pair<std::string, uint64_t>>& out, size_t limit);
  uint16_t bound_port() const { return bound_port_; }

 private:
  int listen_socket(std::string& err);
  void print_startup() const;
  void accept_loop();
  static void* setup_entry(void* arg);
  void setup(std::shared_ptr<Conn> c);
  void run_mitm(std::shared_ptr<Conn> c, std::string leftover);
  void run_tunnel(std::shared_ptr<Conn> c, std::string leftover);
  void run_plain(std::shared_ptr<Conn> c, const std::string& head,
                 const std::string& leftover, const std::string& method,
                 const std::string& target, const std::string& version);
  void install_parsers(std::shared_ptr<Conn> c);
  void relay_loop(std::shared_ptr<Conn> c);
  bool pump(Side& src, Side& dst, class HttpParser* parser, char* buf, size_t cap,
            Conn* conn, bool c2s);
  bool dst_write(Side& dst, const char* p, size_t n);
  bool feed_socket(Side& s);
  bool flush_out(Side& s);
  void close_conn(std::shared_ptr<Conn> c);
  void respond(std::shared_ptr<Conn> c, int code, const char* reason, const std::string& msg);
  void emit_error(std::shared_ptr<Conn> c, const std::string& msg);
  void block_conn(std::shared_ptr<Conn> c, const std::string& reason);
  void count_host(const std::string& host);
  bool allowed_host(const std::string& host) const;

  Options opt_;
  Logger& log_;
  CertStore* ca_;
  Stats& st_;
  SSL_CTX* sctx_ = nullptr;
  SSL_CTX* uctx_ = nullptr;
  std::string tls_err_;
  std::mutex host_mtx_;
  std::map<std::string, uint64_t> hosts_;
  std::atomic<int> active_{0};
  uint16_t bound_port_ = 0;
};

void proxy_request_stop();
bool proxy_stopped();

}  // namespace shijima
