#pragma once
#include <openssl/ssl.h>

#include <deque>
#include <map>
#include <mutex>
#include <string>

namespace shijima {

class CertStore {
 public:
  ~CertStore();
  bool init(const std::string& dir, std::string& err);
  X509* issue(const std::string& host, std::string& err);
  EVP_PKEY* leaf_key() { return leaf_key_; }
  const std::string& ca_path() const { return ca_path_; }
  const std::string& ca_key_path() const { return ca_key_path_; }
  std::string ca_fingerprint();

 private:
  X509* make_leaf(const std::string& host, std::string& err);

  EVP_PKEY* ca_key_ = nullptr;
  X509* ca_cert_ = nullptr;
  EVP_PKEY* leaf_key_ = nullptr;
  std::string dir_;
  std::string ca_path_;
  std::string ca_key_path_;
  std::map<std::string, X509*> cache_;
  std::deque<std::string> lru_;
  std::mutex mtx_;
};

struct TlsPipe {
  SSL* ssl = nullptr;
  BIO* rbio = nullptr;
  BIO* wbio = nullptr;
  bool is_tls() const { return ssl != nullptr; }
};

class Tls {
 public:
  static SSL_CTX* server_ctx(CertStore* store, std::string& err);
  static SSL_CTX* upstream_ctx(bool insecure, std::string& err);
  static std::string version(SSL* s);
  static std::string cipher(SSL* s);
  static std::string alpn(SSL* s);
  static std::string verify_error(SSL* s);
  static std::string sni(const SSL* s);
  static std::string parse_client_hello_sni(const unsigned char* p, size_t n);
};

bool tls_pipe_init(TlsPipe& p, SSL_CTX* ctx, bool server_side, std::string& err);
bool tls_pipe_handshake(TlsPipe& p, int fd, std::string& err);
void tls_pipe_drain(TlsPipe& p, std::string& out);
void tls_pipe_free(TlsPipe& p);
int tls_ssl_ex_host_index();

}  // namespace shijima
