#include "proxy.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <vector>

#include "http.h"
#include "util.h"

namespace shijima {
namespace {

constexpr size_t kRelayBuf = 16384;
constexpr size_t kHighWater = 256 * 1024;
constexpr size_t kHardCap = 4 * 1024 * 1024;
constexpr size_t kMaxHead = 32768;

volatile sig_atomic_t g_stop = 0;
volatile sig_atomic_t g_listen_fd = -1;
std::atomic<uint64_t> g_next_id{1};

void on_signal(int) {
  g_stop = 1;
  int fd = (int)g_listen_fd;
  if (fd >= 0) close(fd);
}

void set_nonblocking(int fd) {
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void set_socket_timeouts(int fd, int sec) {
  struct timeval tv;
  tv.tv_sec = sec;
  tv.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

std::string socket_name(int fd) {
  struct sockaddr_storage ss;
  socklen_t len = sizeof ss;
  if (getpeername(fd, (struct sockaddr*)&ss, &len) != 0) return "-";
  char host[NI_MAXHOST], serv[NI_MAXSERV];
  if (getnameinfo((struct sockaddr*)&ss, len, host, sizeof host, serv, sizeof serv,
                  NI_NUMERICHOST | NI_NUMERICSERV) != 0)
    return "-";
  if (ss.ss_family == AF_INET6) return std::string("[") + host + "]:" + serv;
  return std::string(host) + ":" + serv;
}

bool send_str(int fd, const std::string& s) {
  size_t off = 0;
  while (off < s.size()) {
    ssize_t w = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
    if (w <= 0) {
      if (w < 0 && errno == EINTR) continue;
      return false;
    }
    off += (size_t)w;
  }
  return true;
}

bool read_head(int fd, std::string& head, std::string& leftover, size_t limit, int timeout_ms,
               std::string& err) {
  head.clear();
  leftover.clear();
  int64_t deadline = (int64_t)mono_ms() + timeout_ms;
  char buf[4096];
  for (;;) {
    int64_t left = deadline - (int64_t)mono_ms();
    if (left <= 0) {
      err = "读取请求头超时";
      return false;
    }
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int rc = poll(&pfd, 1, (int)std::min<int64_t>(left, 1000));
    if (rc < 0) {
      if (errno == EINTR) continue;
      err = strerror(errno);
      return false;
    }
    if (rc == 0) continue;
    ssize_t n = recv(fd, buf, sizeof buf, MSG_DONTWAIT);
    if (n > 0) {
      head.append(buf, (size_t)n);
      size_t pos = head.find("\r\n\r\n");
      if (pos != std::string::npos) {
        leftover = head.substr(pos + 4);
        head.resize(pos + 4);
        return true;
      }
      if (head.size() > limit) {
        err = "请求头过大";
        return false;
      }
    } else if (n == 0) {
      err = "客户端关闭连接";
      return false;
    } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      err = strerror(errno);
      return false;
    }
  }
}

int peek_byte(int fd, int timeout_ms) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  int rc = poll(&pfd, 1, timeout_ms);
  if (rc <= 0) return rc;
  unsigned char b = 0;
  ssize_t n = recv(fd, &b, 1, MSG_PEEK);
  if (n <= 0) return -1;
  return b;
}

std::string peek_sni(int fd) {
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  if (poll(&pfd, 1, 2000) <= 0) return "";
  unsigned char buf[8192];
  ssize_t n = recv(fd, buf, sizeof buf, MSG_PEEK);
  if (n <= 0) return "";
  return Tls::parse_client_hello_sni(buf, (size_t)n);
}

bool parse_request_line(const std::string& head, std::string& method, std::string& target,
                        std::string& version) {
  size_t e = head.find("\r\n");
  std::string line = head.substr(0, e == std::string::npos ? head.size() : e);
  size_t a = line.find(' ');
  if (a == std::string::npos) return false;
  size_t b = line.rfind(' ');
  if (b == std::string::npos || b <= a) return false;
  method = line.substr(0, a);
  target = line.substr(a + 1, b - a - 1);
  version = line.substr(b + 1);
  return !method.empty() && !target.empty();
}

std::string rewrite_head(const std::string& head, const std::string& new_line) {
  size_t e = head.find("\r\n");
  if (e == std::string::npos) return new_line + "\r\n\r\n";
  return new_line + head.substr(e);
}

bool split_authority(const std::string& auth, std::string& host, uint16_t& port,
                     uint16_t defport) {
  host = auth;
  port = defport;
  if (!auth.empty() && auth[0] == '[') {
    size_t close = auth.find(']');
    if (close == std::string::npos) return false;
    host = auth.substr(1, close - 1);
    if (close + 1 < auth.size() && auth[close + 1] == ':')
      port = (uint16_t)atoi(auth.c_str() + close + 2);
  } else {
    size_t colon = auth.rfind(':');
    if (colon != std::string::npos) {
      host = auth.substr(0, colon);
      port = (uint16_t)atoi(auth.c_str() + colon + 1);
    }
  }
  return !host.empty() && port > 0;
}

bool parse_abs_uri(const std::string& uri, std::string& host, uint16_t& port,
                   std::string& path) {
  if (uri.compare(0, 7, "http://") != 0) return false;
  std::string rest = uri.substr(7);
  size_t slash = rest.find('/');
  std::string auth = slash == std::string::npos ? rest : rest.substr(0, slash);
  path = slash == std::string::npos ? "/" : rest.substr(slash);
  return split_authority(auth, host, port, 80);
}

int dial(const std::string& host, uint16_t port, int timeout_ms, std::string& err) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  char ps[8];
  snprintf(ps, sizeof ps, "%u", (unsigned)port);
  struct addrinfo* res = nullptr;
  int gai = getaddrinfo(host.c_str(), ps, &hints, &res);
  if (gai != 0) {
    err = std::string("解析 ") + host + " 失败: " + gai_strerror(gai);
    return -1;
  }
  int fd = -1;
  for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
    fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) continue;
    set_nonblocking(fd);
    int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
    if (rc == 0) break;
    if (errno == EINPROGRESS) {
      struct pollfd pfd;
      pfd.fd = fd;
      pfd.events = POLLOUT;
      pfd.revents = 0;
      int pr = poll(&pfd, 1, timeout_ms);
      if (pr > 0) {
        int soerr = 0;
        socklen_t sl = sizeof soerr;
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr == 0) break;
        err = strerror(soerr);
      } else {
        err = "连接超时";
      }
    } else {
      err = strerror(errno);
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  if (fd < 0) return -1;
  int fl = fcntl(fd, F_GETFL, 0);
  if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
  int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  set_socket_timeouts(fd, 20);
  return fd;
}

int try_bind(const std::string& addr, uint16_t port, int& out_fd, uint16_t& actual,
             std::string& err) {
  struct addrinfo hints;
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  char ps[8];
  snprintf(ps, sizeof ps, "%u", (unsigned)port);
  struct addrinfo* res = nullptr;
  int gai = getaddrinfo(addr.empty() ? nullptr : addr.c_str(), ps, &hints, &res);
  if (gai != 0) {
    err = std::string("监听地址无效: ") + gai_strerror(gai);
    return -1;
  }
  int last_err = -1;
  bool busy = false;
  for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
    int fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
    if (fd < 0) {
      last_err = errno;
      continue;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (ai->ai_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    if (bind(fd, ai->ai_addr, ai->ai_addrlen) != 0) {
      last_err = errno;
      if (errno == EADDRINUSE) busy = true;
      close(fd);
      continue;
    }
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getsockname(fd, (struct sockaddr*)&ss, &sl) == 0) {
      if (ss.ss_family == AF_INET)
        actual = ntohs(((struct sockaddr_in*)&ss)->sin_port);
      else if (ss.ss_family == AF_INET6)
        actual = ntohs(((struct sockaddr_in6*)&ss)->sin6_port);
    }
    out_fd = fd;
    freeaddrinfo(res);
    return 0;
  }
  freeaddrinfo(res);
  if (busy) {
    err = "端口被占用";
    return 1;
  }
  err = last_err >= 0 ? strerror(last_err) : "绑定失败";
  return -1;
}

}  // namespace

struct Proxy::Side {
  int fd = -1;
  TlsPipe tls;
  std::string out;
  bool rd_eof = false;
  bool wr_shut = false;
};

struct Proxy::Conn {
  uint64_t id = 0;
  Side cli;
  Side srv;
  std::string client_addr;
  std::string host;
  uint16_t port = 0;
  std::string scheme = "https";
  std::string proto;
  std::string sni;
  bool mitm = false;
  bool tunnel = false;
  bool upgraded = false;
  std::atomic<uint64_t> up{0};
  std::atomic<uint64_t> down{0};
  std::atomic<bool> closed{false};
  HttpParser* req = nullptr;
  HttpParser* resp = nullptr;
  std::string last_method;
  uint64_t t0 = 0;
};

struct SetupJob {
  Proxy* p;
  std::shared_ptr<Proxy::Conn> c;
};

void proxy_request_stop() { on_signal(0); }
bool proxy_stopped() { return g_stop != 0; }

Proxy::Proxy(const Options& opt, Logger& log, CertStore* ca, Stats& st)
    : opt_(opt), log_(log), ca_(ca), st_(st) {
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);
}

Proxy::~Proxy() {
  if (sctx_) SSL_CTX_free(sctx_);
  if (uctx_) SSL_CTX_free(uctx_);
}

bool Proxy::init_tls(std::string& err) {
  if (!opt_.mitm) return true;
  if (!ca_) {
    err = "MITM 模式需要本地 CA";
    return false;
  }
  sctx_ = Tls::server_ctx(ca_, err);
  if (!sctx_) return false;
  uctx_ = Tls::upstream_ctx(opt_.insecure, err);
  if (!uctx_) return false;
  return true;
}

int Proxy::listen_socket(std::string& err) {
  std::vector<int> ports;
  if (opt_.strict_port || opt_.port == 0) {
    ports.push_back((int)opt_.port);
  } else {
    for (int i = 0; i < 20; ++i) {
      int p = (int)opt_.port + i;
      if (p > 65535) break;
      ports.push_back(p);
    }
    ports.push_back(0);
  }
  std::string last;
  for (int want : ports) {
    int fd = -1;
    uint16_t actual = 0;
    int r = try_bind(opt_.bind_addr, (uint16_t)want, fd, actual, last);
    if (r == 0) {
      bound_port_ = actual;
      return fd;
    }
    if (r < 0) {
      err = last;
      return -1;
    }
  }
  err = last.empty() ? "无法绑定监听端口" : last;
  return -1;
}

void Proxy::print_startup() const {
  fprintf(stderr, "shijima 0.1.0 — 本地 HTTPS 抓包代理\n");
  fprintf(stderr, "  监听       http://%s:%u\n", opt_.bind_addr.c_str(), bound_port_);
  if (opt_.port != 0 && bound_port_ != opt_.port)
    fprintf(stderr, "  [提示] 端口 %u 被占用，已改用 %u\n", opt_.port, bound_port_);
  fprintf(stderr, "  模式       %s\n",
          opt_.mitm ? (opt_.insecure ? "MITM（不校验上游证书）" : "MITM（解密 HTTPS）")
                    : "隧道（不解密）");
  if (opt_.mitm && ca_) fprintf(stderr, "  CA 证书    %s\n", ca_->ca_path().c_str());
  if (opt_.log.file)
    fprintf(stderr, "  抓包文件   %s（%s）\n", opt_.log.path.c_str(), opt_.log.format.c_str());
  if (opt_.filter && opt_.filter->size() > 0)
    fprintf(stderr, "  过滤规则   %zu 条%s\n", opt_.filter->size(),
            opt_.filter->has_allow() ? "（存在 allow，默认拒绝）" : "");
  if (opt_.tui) fprintf(stderr, "  TUI        已启用（d 拦截 / a 允许 / c 清空 / q 退出）\n");
  fprintf(stderr, "  代理用法   export https_proxy=http://127.0.0.1:%u http_proxy=http://127.0.0.1:%u\n",
          bound_port_, bound_port_);
  if (opt_.mitm)
    fprintf(stderr, "  提示       首次使用需把 CA 证书装进信任库；按下 Ctrl-C 退出并打印概要\n");
}

int Proxy::run() {
  std::string err;
  int fd = listen_socket(err);
  if (fd < 0) {
    fprintf(stderr, "shijima: %s\n", err.c_str());
    return 1;
  }
  g_listen_fd = fd;
  if (listen(fd, 128) != 0) {
    fprintf(stderr, "shijima: listen 失败: %s\n", strerror(errno));
    close(fd);
    return 1;
  }
  print_startup();
  accept_loop();
  g_listen_fd = -1;
  for (int i = 0; i < 50 && active_.load() > 0; ++i) usleep(100000);
  return 0;
}

void Proxy::stop() { proxy_request_stop(); }

void Proxy::accept_loop() {
  while (!g_stop) {
    int fd = (int)g_listen_fd;
    if (fd < 0) break;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int cfd = accept4(fd, (struct sockaddr*)&ss, &sl, SOCK_CLOEXEC);
    if (cfd < 0) {
      if (errno == EINTR) continue;
      if (g_stop) break;
      if (errno == EBADF || errno == EINVAL) break;
      usleep(10000);
      continue;
    }
    if (active_.load() >= opt_.max_conn) {
      static const char kBusy[] =
          "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
      send(cfd, kBusy, sizeof kBusy - 1, MSG_NOSIGNAL);
      close(cfd);
      continue;
    }
    int one = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
    auto c = std::make_shared<Conn>();
    c->cli.fd = cfd;
    c->id = g_next_id.fetch_add(1);
    active_.fetch_add(1);
    auto* job = new SetupJob{this, c};
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 256 * 1024);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, setup_entry, job) != 0) {
      delete job;
      active_.fetch_sub(1);
      close(cfd);
    }
    pthread_attr_destroy(&attr);
  }
}

void* Proxy::setup_entry(void* arg) {
  auto* job = static_cast<SetupJob*>(arg);
  job->p->setup(job->c);
  delete job;
  return nullptr;
}

void Proxy::setup(std::shared_ptr<Conn> c) {
  c->client_addr = socket_name(c->cli.fd);
  std::string head, leftover, err;
  if (!read_head(c->cli.fd, head, leftover, kMaxHead, 15000, err)) {
    emit_error(c, err);
    close_conn(c);
    return;
  }
  std::string method, target, version;
  if (!parse_request_line(head, method, target, version)) {
    respond(c, 400, "Bad Request", "无法解析请求行");
    return;
  }
  st_.conns++;
  if (method == "CONNECT") {
    std::string host;
    uint16_t port = 443;
    if (!split_authority(target, host, port, 443)) {
      respond(c, 400, "Bad Request", "CONNECT 目标无效");
      return;
    }
    c->host = host;
    c->port = port;
    c->scheme = "https";
    if (!allowed_host(host)) {
      block_conn(c, "命中过滤规则（CONNECT）");
      return;
    }
    if (!send_str(c->cli.fd, "HTTP/1.1 200 Connection established\r\n\r\n")) {
      close_conn(c);
      return;
    }
    bool use_mitm = opt_.mitm;
    int first = peek_byte(c->cli.fd, 5000);
    if (first < 0) {
      close_conn(c);
      return;
    }
    if (first != 0x16) use_mitm = false;
    if (!use_mitm) {
      run_tunnel(c, leftover);
      return;
    }
    run_mitm(c, leftover);
    return;
  }
  run_plain(c, head, leftover, method, target, version);
}

void Proxy::run_mitm(std::shared_ptr<Conn> c, std::string leftover) {
  c->mitm = true;
  st_.mitm++;
  std::string err;
  int ufd = dial(c->host, c->port, 10000, err);
  if (ufd < 0) {
    emit_error(c, "连接上游失败: " + err);
    close_conn(c);
    return;
  }
  c->srv.fd = ufd;

  if (!tls_pipe_init(c->cli.tls, sctx_, true, err)) {
    emit_error(c, err);
    close_conn(c);
    return;
  }
  SSL_set_ex_data(c->cli.tls.ssl, tls_ssl_ex_host_index(), &c->host);
  if (!leftover.empty()) BIO_write(c->cli.tls.rbio, leftover.data(), (int)leftover.size());
  if (!tls_pipe_handshake(c->cli.tls, c->cli.fd, err)) {
    emit_error(c, "客户端 TLS 握手失败: " + err);
    close_conn(c);
    return;
  }
  std::string csni = Tls::sni(c->cli.tls.ssl);
  if (!csni.empty()) c->sni = csni;

  if (!tls_pipe_init(c->srv.tls, uctx_, false, err)) {
    emit_error(c, err);
    close_conn(c);
    return;
  }
  SSL_set_tlsext_host_name(c->srv.tls.ssl, c->host.c_str());
  if (opt_.insecure) {
    SSL_set_verify(c->srv.tls.ssl, SSL_VERIFY_NONE, nullptr);
  } else {
    SSL_set_verify(c->srv.tls.ssl, SSL_VERIFY_PEER, nullptr);
    if (is_ip_literal(c->host)) {
      X509_VERIFY_PARAM* param = SSL_get0_param(c->srv.tls.ssl);
      X509_VERIFY_PARAM_set1_ip_asc(param, c->host.c_str());
    } else {
      SSL_set1_host(c->srv.tls.ssl, c->host.c_str());
    }
  }
  if (!tls_pipe_handshake(c->srv.tls, c->srv.fd, err)) {
    std::string v = Tls::verify_error(c->srv.tls.ssl);
    emit_error(c, "上游 TLS 握手失败: " + (v.empty() ? err : v));
    close_conn(c);
    return;
  }
  c->proto = Tls::version(c->cli.tls.ssl);
  std::string alpn = Tls::alpn(c->cli.tls.ssl);
  if (!alpn.empty()) c->proto += " " + alpn;

  Record r;
  r.kind = "connection";
  r.conn = c->id;
  r.time = now_iso_ms();
  r.src = c->client_addr;
  r.host = c->host;
  r.port = c->port;
  r.scheme = c->scheme;
  r.proto = c->proto;
  r.note = "解密转发";
  log_.emit(r);

  install_parsers(c);
  relay_loop(c);
  close_conn(c);
}

void Proxy::run_tunnel(std::shared_ptr<Conn> c, std::string leftover) {
  c->tunnel = true;
  st_.tunnels++;
  std::string err;
  int ufd = dial(c->host, c->port, 10000, err);
  if (ufd < 0) {
    emit_error(c, "连接上游失败: " + err);
    close_conn(c);
    return;
  }
  c->srv.fd = ufd;
  if (leftover.empty()) {
    c->sni = peek_sni(c->cli.fd);
  } else {
    c->sni = Tls::parse_client_hello_sni((const unsigned char*)leftover.data(), leftover.size());
  }
  c->proto = "tunnel";
  c->srv.out += leftover;

  Record r;
  r.kind = "connection";
  r.conn = c->id;
  r.time = now_iso_ms();
  r.src = c->client_addr;
  r.host = c->host;
  r.port = c->port;
  r.scheme = c->scheme;
  r.proto = "tunnel";
  r.note = c->sni.empty() ? "隧道（未解密）" : ("隧道（未解密） SNI=" + c->sni);
  log_.emit(r);

  relay_loop(c);
  close_conn(c);
}

void Proxy::run_plain(std::shared_ptr<Conn> c, const std::string& head,
                      const std::string& leftover, const std::string& method,
                      const std::string& target, const std::string& version) {
  std::string host, path;
  uint16_t port = 80;
  if (!parse_abs_uri(target, host, port, path)) {
    respond(c, 400, "Bad Request", "只支持 http:// 绝对地址或 CONNECT");
    return;
  }
  c->host = host;
  c->port = port;
  c->scheme = "http";
  if (!allowed_host(host)) {
    block_conn(c, "命中过滤规则（HTTP）");
    return;
  }
  std::string err;
  int ufd = dial(host, port, 10000, err);
  if (ufd < 0) {
    emit_error(c, "连接上游失败: " + err);
    close_conn(c);
    return;
  }
  c->srv.fd = ufd;

  std::string newline = method + " " + path + " " + (version.empty() ? "HTTP/1.1" : version);
  std::string rhead = rewrite_head(head, newline);
  c->proto = version.empty() ? "HTTP/1.1" : version;
  install_parsers(c);
  c->req->feed(rhead.data(), rhead.size());
  if (!leftover.empty()) c->req->feed(leftover.data(), leftover.size());
  c->srv.out += rhead;
  c->srv.out += leftover;

  Record r;
  r.kind = "connection";
  r.conn = c->id;
  r.time = now_iso_ms();
  r.src = c->client_addr;
  r.host = c->host;
  r.port = c->port;
  r.scheme = c->scheme;
  r.proto = c->proto;
  r.note = "HTTP 代理";
  log_.emit(r);

  relay_loop(c);
  close_conn(c);
}

void Proxy::install_parsers(std::shared_ptr<Conn> c) {
  Conn* cp = c.get();
  c->req = new HttpParser(true, kMaxHead, opt_.body_limit);
  c->resp = new HttpParser(false, kMaxHead, opt_.body_limit);
  c->req->on_headers([cp](HttpMessage& m) {
    cp->t0 = mono_ms();
    cp->last_method = m.method;
    if (cp->resp) cp->resp->set_no_body_hint(m.method == "HEAD");
  });
  c->req->on_done([this, cp](HttpMessage& m) {
    Record r;
    r.kind = "request";
    r.conn = cp->id;
    r.time = now_iso_ms();
    r.src = cp->client_addr;
    r.scheme = cp->scheme;
    r.host = cp->host;
    r.port = cp->port;
    r.proto = cp->proto;
    r.method = m.method;
    r.target = m.target;
    r.content_type = m.headers.get("content-type");
    r.size = m.body_size;
    r.preview = m.body_preview;
    r.preview_binary = is_binary_content_type(r.content_type, m.headers.get("content-encoding")) ||
                       looks_binary(m.body_preview);
    if (r.preview_binary) r.preview = hexdump(m.body_preview, 256);
    log_.emit(r);
    st_.requests++;
    count_host(cp->host);
  });
  c->resp->on_headers([cp](HttpMessage& m) {
    if (m.status == 101) {
      cp->upgraded = true;
      if (cp->req) cp->req->stop();
      if (cp->resp) cp->resp->stop();
    }
  });
  c->resp->on_done([this, cp](HttpMessage& m) {
    Record r;
    r.kind = "response";
    r.conn = cp->id;
    r.time = now_iso_ms();
    r.src = cp->client_addr;
    r.scheme = cp->scheme;
    r.host = cp->host;
    r.port = cp->port;
    r.proto = cp->proto;
    r.status = m.status;
    r.content_type = m.headers.get("content-type");
    r.size = m.body_size;
    r.duration_ms = cp->t0 ? (mono_ms() - cp->t0) : 0;
    r.preview = m.body_preview;
    r.preview_binary = is_binary_content_type(r.content_type, m.headers.get("content-encoding")) ||
                       looks_binary(m.body_preview);
    if (r.preview_binary) r.preview = hexdump(m.body_preview, 256);
    log_.emit(r);
    st_.responses++;
  });
}

bool Proxy::feed_socket(Side& s) {
  if (!s.tls.is_tls() || s.rd_eof) return false;
  if (BIO_ctrl_pending(s.tls.rbio) > 32768) return false;
  char buf[8192];
  ssize_t n = recv(s.fd, buf, sizeof buf, MSG_DONTWAIT);
  if (n > 0) {
    BIO_write(s.tls.rbio, buf, (int)n);
    return true;
  }
  if (n == 0) {
    s.rd_eof = true;
    return true;
  }
  if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return false;
  s.rd_eof = true;
  return true;
}

bool Proxy::flush_out(Side& s) {
  if (s.out.empty()) return false;
  ssize_t n = send(s.fd, s.out.data(), s.out.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
  if (n > 0) {
    if ((size_t)n >= s.out.size())
      s.out.clear();
    else
      s.out.erase(0, (size_t)n);
    return true;
  }
  if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return false;
  s.out.clear();
  s.rd_eof = true;
  return false;
}

bool Proxy::dst_write(Side& dst, const char* p, size_t n) {
  if (!dst.tls.is_tls()) {
    if (dst.out.size() + n > kHardCap) return false;
    dst.out.append(p, n);
    return true;
  }
  size_t off = 0;
  while (off < n) {
    int w = SSL_write(dst.tls.ssl, p + off, (int)std::min<size_t>(n - off, 1u << 20));
    if (w <= 0) {
      int e = SSL_get_error(dst.tls.ssl, w);
      (void)e;
      return false;
    }
    off += (size_t)w;
    tls_pipe_drain(dst.tls, dst.out);
  }
  return true;
}

bool Proxy::pump(Side& src, Side& dst, HttpParser* parser, char* buf, size_t cap, Conn* conn,
                 bool c2s) {
  if (src.rd_eof) return false;
  ssize_t n = 0;
  if (src.tls.is_tls()) {
    int r = SSL_read(src.tls.ssl, buf, (int)cap);
    if (r > 0) {
      n = r;
      tls_pipe_drain(src.tls, src.out);
    } else {
      int e = SSL_get_error(src.tls.ssl, r);
      if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return false;
      src.rd_eof = true;
      return true;
    }
  } else {
    n = recv(src.fd, buf, cap, MSG_DONTWAIT);
    if (n <= 0) {
      if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return false;
      src.rd_eof = true;
      return true;
    }
  }
  if (c2s)
    conn->up += (uint64_t)n;
  else
    conn->down += (uint64_t)n;
  if (parser && !conn->upgraded) parser->feed(buf, (size_t)n);
  return dst_write(dst, buf, (size_t)n);
}

void Proxy::relay_loop(std::shared_ptr<Conn> c) {
  set_nonblocking(c->cli.fd);
  if (c->srv.fd >= 0) set_nonblocking(c->srv.fd);
  std::vector<char> buf(kRelayBuf);
  uint64_t last = mono_ms();
  while (!g_stop) {
    bool busy = false;
    busy |= feed_socket(c->cli);
    busy |= feed_socket(c->srv);
    if (c->srv.out.size() < kHighWater)
      busy |= pump(c->cli, c->srv, c->req, buf.data(), buf.size(), c.get(), true);
    if (c->cli.out.size() < kHighWater)
      busy |= pump(c->srv, c->cli, c->resp, buf.data(), buf.size(), c.get(), false);
    busy |= flush_out(c->cli);
    busy |= flush_out(c->srv);

    if (c->cli.rd_eof && c->srv.out.empty() && !c->srv.wr_shut) {
      shutdown(c->srv.fd, SHUT_WR);
      c->srv.wr_shut = true;
    }
    if (c->srv.rd_eof && c->cli.out.empty() && !c->cli.wr_shut) {
      shutdown(c->cli.fd, SHUT_WR);
      c->cli.wr_shut = true;
    }
    if (c->cli.rd_eof && c->srv.rd_eof && c->cli.out.empty() && c->srv.out.empty()) break;
    if (busy) {
      last = mono_ms();
      continue;
    }
    short ev_cli = 0, ev_srv = 0;
    if (!c->cli.rd_eof && c->srv.out.size() < kHighWater) ev_cli |= POLLIN;
    if (!c->cli.out.empty()) ev_cli |= POLLOUT;
    if (!c->srv.rd_eof && c->cli.out.size() < kHighWater) ev_srv |= POLLIN;
    if (!c->srv.out.empty()) ev_srv |= POLLOUT;
    if (!ev_cli && !ev_srv) break;
    struct pollfd pfd[2];
    pfd[0].fd = c->cli.fd;
    pfd[0].events = ev_cli;
    pfd[0].revents = 0;
    pfd[1].fd = c->srv.fd;
    pfd[1].events = ev_srv;
    pfd[1].revents = 0;
    int rc = poll(pfd, 2, 500);
    if (rc < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (rc > 0) {
      for (int i = 0; i < 2; ++i) {
        if (pfd[i].revents & (POLLERR | POLLNVAL | POLLHUP))
          (i == 0 ? c->cli : c->srv).rd_eof = true;
      }
    }
    if (mono_ms() - last > (uint64_t)opt_.idle_timeout * 1000) break;
  }
  if (c->req) c->req->finish();
  if (c->resp) c->resp->finish();
}

void Proxy::close_conn(std::shared_ptr<Conn> c) {
  if (c->closed.exchange(true)) return;
  if (c->tunnel) {
    Record r;
    r.kind = "tunnel";
    r.conn = c->id;
    r.time = now_iso_ms();
    r.src = c->client_addr;
    r.scheme = c->scheme;
    r.host = c->host;
    r.port = c->port;
    r.proto = "tunnel";
    r.size = c->down.load();
    r.note = "↑" + fmt_size(c->up.load()) + " ↓" + fmt_size(c->down.load());
    if (!c->sni.empty()) r.note += " SNI=" + c->sni;
    log_.emit(r);
  }
  tls_pipe_free(c->cli.tls);
  tls_pipe_free(c->srv.tls);
  if (c->cli.fd >= 0) close(c->cli.fd);
  if (c->srv.fd >= 0) close(c->srv.fd);
  c->cli.fd = -1;
  c->srv.fd = -1;
  delete c->req;
  delete c->resp;
  c->req = nullptr;
  c->resp = nullptr;
  st_.up_bytes += c->up.load();
  st_.down_bytes += c->down.load();
  active_.fetch_sub(1);
}

void Proxy::respond(std::shared_ptr<Conn> c, int code, const char* reason,
                    const std::string& msg) {
  std::string body = msg + "\n";
  char hdr[256];
  snprintf(hdr, sizeof hdr,
           "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "
           "%zu\r\nConnection: close\r\n\r\n",
           code, reason, body.size());
  send_str(c->cli.fd, std::string(hdr) + body);
  emit_error(c, msg);
  close_conn(c);
}

void Proxy::emit_error(std::shared_ptr<Conn> c, const std::string& msg) {
  st_.errors++;
  Record r;
  r.kind = "error";
  r.conn = c->id;
  r.time = now_iso_ms();
  r.src = c->client_addr;
  r.host = c->host;
  r.port = c->port;
  r.note = msg;
  log_.emit(r);
}

bool Proxy::allowed_host(const std::string& host) const {
  if (!opt_.filter) return true;
  return opt_.filter->allowed(host);
}

void Proxy::block_conn(std::shared_ptr<Conn> c, const std::string& reason) {
  st_.blocked++;
  Record r;
  r.kind = "blocked";
  r.conn = c->id;
  r.time = now_iso_ms();
  r.src = c->client_addr;
  r.scheme = c->scheme;
  r.host = c->host;
  r.port = c->port;
  r.note = reason;
  log_.emit(r);
  static const char k403[] =
      "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
  send_str(c->cli.fd, k403);
  close_conn(c);
}

void Proxy::count_host(const std::string& host) {
  std::lock_guard<std::mutex> lock(host_mtx_);
  hosts_[host]++;
}

void Proxy::top_hosts(std::vector<std::pair<std::string, uint64_t>>& out, size_t limit) {
  std::lock_guard<std::mutex> lock(host_mtx_);
  out.assign(hosts_.begin(), hosts_.end());
  std::sort(out.begin(), out.end(),
            [](const std::pair<std::string, uint64_t>& a,
               const std::pair<std::string, uint64_t>& b) {
              if (a.second != b.second) return a.second > b.second;
              return a.first < b.first;
            });
  if (out.size() > limit) out.resize(limit);
}

}  // namespace shijima
