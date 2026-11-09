#include "tls.h"

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <mutex>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include "util.h"

namespace shijima {
namespace {

std::string openssl_err() {
  unsigned long e = ERR_get_error();
  if (!e) return "unknown";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof buf);
  while (ERR_get_error() != 0) {
  }
  return buf;
}

EVP_PKEY* make_ec_key(std::string& err) {
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY* key = nullptr;
  if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
      EVP_PKEY_keygen(ctx, &key) <= 0) {
    err = "生成 EC 密钥失败: " + openssl_err();
    if (key) {
      EVP_PKEY_free(key);
      key = nullptr;
    }
  }
  if (ctx) EVP_PKEY_CTX_free(ctx);
  return key;
}

bool add_ext(X509* cert, X509* issuer, int nid, const char* value) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
  X509_EXTENSION* ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
  if (!ex) return false;
  X509_add_ext(cert, ex, -1);
  X509_EXTENSION_free(ex);
  return true;
}

bool send_all_blocking(int fd, const char* p, size_t n) {
  while (n > 0) {
    ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
    if (w <= 0) {
      if (w < 0 && errno == EINTR) continue;
      return false;
    }
    p += w;
    n -= (size_t)w;
  }
  return true;
}

int g_ex_host = -2;

int sni_cb(SSL* ssl, int* al, void* arg) {
  auto* store = static_cast<CertStore*>(arg);
  std::string host;
  const char* name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (name && *name) {
    host = name;
  } else {
    auto* hp = static_cast<std::string*>(SSL_get_ex_data(ssl, tls_ssl_ex_host_index()));
    if (hp) host = *hp;
  }
  if (host.empty()) {
    *al = SSL_AD_UNRECOGNIZED_NAME;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  std::string err;
  X509* cert = store->issue(host, err);
  if (!cert || SSL_use_certificate(ssl, cert) != 1 ||
      SSL_use_PrivateKey(ssl, store->leaf_key()) != 1) {
    fprintf(stderr, "shijima: 签发 %s 的证书失败: %s\n", host.c_str(),
            err.empty() ? openssl_err().c_str() : err.c_str());
    *al = SSL_AD_INTERNAL_ERROR;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  return SSL_TLSEXT_ERR_OK;
}

int alpn_select_cb(SSL*, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void*) {
  static const char kWant[] = "http/1.1";
  unsigned int i = 0;
  while (i < inlen) {
    unsigned char l = in[i];
    if (l == 0 || i + 1u + l > inlen) break;
    if (l == 8 && memcmp(in + i + 1, kWant, 8) == 0) {
      *out = in + i + 1;
      *outlen = 8;
      return SSL_TLSEXT_ERR_OK;
    }
    i += 1u + l;
  }
  return SSL_TLSEXT_ERR_NOACK;
}

const char kAlpnHttp11[] = "\x08http/1.1";

}  // namespace

int tls_ssl_ex_host_index() {
  static std::once_flag once;
  std::call_once(once, [] {
    g_ex_host = SSL_get_ex_new_index(0, (void*)"shijima-host", nullptr, nullptr, nullptr);
  });
  return g_ex_host;
}

CertStore::~CertStore() {
  if (ca_cert_) X509_free(ca_cert_);
  if (ca_key_) EVP_PKEY_free(ca_key_);
  if (leaf_key_) EVP_PKEY_free(leaf_key_);
  for (auto& kv : cache_) X509_free(kv.second);
}

bool CertStore::init(const std::string& dir, std::string& err) {
  dir_ = dir;
  if (!ensure_dir(dir_, 0700)) {
    err = "无法创建 CA 目录: " + dir_;
    return false;
  }
  ca_path_ = dir_ + "/ca.pem";
  ca_key_path_ = dir_ + "/ca-key.pem";

  if (file_exists(ca_path_) && file_exists(ca_key_path_)) {
    FILE* f = fopen(ca_path_.c_str(), "r");
    if (!f) {
      err = "无法读取 " + ca_path_;
      return false;
    }
    ca_cert_ = PEM_read_X509(f, nullptr, nullptr, nullptr);
    fclose(f);
    f = fopen(ca_key_path_.c_str(), "r");
    if (!f) {
      err = "无法读取 " + ca_key_path_;
      return false;
    }
    ca_key_ = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
    fclose(f);
    if (!ca_cert_ || !ca_key_ || X509_check_private_key(ca_cert_, ca_key_) != 1) {
      err = "CA 证书与私钥不匹配，请删除 " + dir_ + " 后重试";
      return false;
    }
  } else {
    ca_key_ = make_ec_key(err);
    if (!ca_key_) return false;
    ca_cert_ = X509_new();
    if (!ca_cert_) {
      err = "创建 CA 证书失败";
      return false;
    }
    X509_set_version(ca_cert_, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca_cert_), (long)(rand_u64() & 0x7fffffff));
    X509_gmtime_adj(X509_getm_notBefore(ca_cert_), 0);
    X509_gmtime_adj(X509_getm_notAfter(ca_cert_), 3600L * 24 * 365 * 10);
    X509_set_pubkey(ca_cert_, ca_key_);
    X509_NAME* nm = X509_get_subject_name(ca_cert_);
    X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)"shijima", -1, -1, 0);
    X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
                               (const unsigned char*)"shijima Local CA", -1, -1, 0);
    X509_set_issuer_name(ca_cert_, nm);
    add_ext(ca_cert_, ca_cert_, NID_basic_constraints, "critical,CA:TRUE,pathlen:0");
    add_ext(ca_cert_, ca_cert_, NID_key_usage, "critical,keyCertSign,cRLSign");
    add_ext(ca_cert_, ca_cert_, NID_subject_key_identifier, "hash");
    if (X509_sign(ca_cert_, ca_key_, EVP_sha256()) <= 0) {
      err = "CA 签名失败: " + openssl_err();
      return false;
    }

    FILE* f = fopen(ca_path_.c_str(), "w");
    if (!f || PEM_write_X509(f, ca_cert_) != 1) {
      err = "写入 " + ca_path_ + " 失败";
      if (f) fclose(f);
      return false;
    }
    fclose(f);

    int fd = open(ca_key_path_.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
      err = "写入 " + ca_key_path_ + " 失败";
      return false;
    }
    FILE* fk = fdopen(fd, "w");
    if (!fk || PEM_write_PrivateKey(fk, ca_key_, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
      err = "写入 CA 私钥失败";
      if (fk) fclose(fk);
      return false;
    }
    fclose(fk);
  }

  leaf_key_ = make_ec_key(err);
  return leaf_key_ != nullptr;
}

X509* CertStore::issue(const std::string& host_raw, std::string& err) {
  std::string host = to_lower(host_raw);
  while (!host.empty() && host.back() == '.') host.pop_back();
  if (host.empty()) {
    err = "空主机名";
    return nullptr;
  }
  std::lock_guard<std::mutex> lock(mtx_);
  auto it = cache_.find(host);
  if (it != cache_.end()) return it->second;
  X509* cert = make_leaf(host, err);
  if (!cert) return nullptr;
  cache_[host] = cert;
  lru_.push_back(host);
  while (lru_.size() > 128) {
    const std::string& old = lru_.front();
    auto oit = cache_.find(old);
    if (oit != cache_.end()) {
      X509_free(oit->second);
      cache_.erase(oit);
    }
    lru_.pop_front();
  }
  return cert;
}

X509* CertStore::make_leaf(const std::string& host, std::string& err) {
  X509* x = X509_new();
  if (!x) {
    err = "创建证书失败";
    return nullptr;
  }
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), (long)(rand_u64() & 0x7fffffff));
  X509_gmtime_adj(X509_getm_notBefore(x), -86400L);
  X509_gmtime_adj(X509_getm_notAfter(x), 397L * 86400);
  X509_set_pubkey(x, leaf_key_);
  X509_NAME* nm = X509_get_subject_name(x);
  std::string cn = host.size() > 64 ? host.substr(0, 64) : host;
  X509_NAME_add_entry_by_txt(nm, "O", MBSTRING_ASC, (const unsigned char*)"shijima", -1, -1, 0);
  X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC, (const unsigned char*)cn.c_str(), -1, -1, 0);
  X509_set_issuer_name(x, X509_get_subject_name(ca_cert_));

  std::string san = is_ip_literal(host) ? ("IP:" + host) : ("DNS:" + host);
  bool ok = add_ext(x, ca_cert_, NID_basic_constraints, "critical,CA:FALSE") &&
            add_ext(x, ca_cert_, NID_key_usage, "critical,digitalSignature") &&
            add_ext(x, ca_cert_, NID_ext_key_usage, "serverAuth") &&
            add_ext(x, ca_cert_, NID_subject_alt_name, san.c_str()) &&
            add_ext(x, ca_cert_, NID_subject_key_identifier, "hash") &&
            add_ext(x, ca_cert_, NID_authority_key_identifier, "keyid:always");
  if (!ok || X509_sign(x, ca_key_, EVP_sha256()) <= 0) {
    err = "签发展示证书失败: " + openssl_err();
    X509_free(x);
    return nullptr;
  }
  return x;
}

std::string CertStore::ca_fingerprint() {
  std::lock_guard<std::mutex> lock(mtx_);
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (!ca_cert_ || X509_digest(ca_cert_, EVP_sha256(), md, &len) != 1) return "";
  std::string out;
  char b[4];
  for (unsigned int i = 0; i < len; ++i) {
    snprintf(b, sizeof b, "%02X", md[i]);
    if (i) out += ":";
    out += b;
  }
  return out;
}

SSL_CTX* Tls::server_ctx(CertStore* store, std::string& err) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
  if (!ctx) {
    err = "创建 TLS 服务端上下文失败: " + openssl_err();
    return nullptr;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
  SSL_CTX_set_tlsext_servername_callback(ctx, sni_cb);
  SSL_CTX_set_tlsext_servername_arg(ctx, store);
  SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, nullptr);
  return ctx;
}

SSL_CTX* Tls::upstream_ctx(bool insecure, std::string& err) {
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  if (!ctx) {
    err = "创建 TLS 客户端上下文失败: " + openssl_err();
    return nullptr;
  }
  SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
  SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
  SSL_CTX_set_alpn_protos(ctx, (const unsigned char*)kAlpnHttp11, sizeof(kAlpnHttp11) - 1);
  if (insecure) {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  } else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_default_verify_paths(ctx);
    const char* candidates[] = {
        getenv("SSL_CERT_FILE"),
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
        "/data/data/com.termux/files/usr/etc/tls/cert.pem",
        nullptr};
    for (int i = 0; candidates[i]; ++i) {
      if (candidates[i] && file_exists(candidates[i]))
        SSL_CTX_load_verify_locations(ctx, candidates[i], nullptr);
    }
  }
  return ctx;
}

std::string Tls::version(SSL* s) { return s ? SSL_get_version(s) : ""; }

std::string Tls::cipher(SSL* s) {
  const SSL_CIPHER* c = s ? SSL_get_current_cipher(s) : nullptr;
  return c ? SSL_CIPHER_get_name(c) : "";
}

std::string Tls::alpn(SSL* s) {
  const unsigned char* p = nullptr;
  unsigned int len = 0;
  if (!s) return "";
  SSL_get0_alpn_selected(s, &p, &len);
  return (p && len) ? std::string((const char*)p, len) : "";
}

std::string Tls::verify_error(SSL* s) {
  long v = s ? SSL_get_verify_result(s) : X509_V_ERR_UNSPECIFIED;
  if (v == X509_V_OK) return "";
  return X509_verify_cert_error_string(v);
}

std::string Tls::sni(const SSL* s) {
  const char* n = s ? SSL_get_servername(s, TLSEXT_NAMETYPE_host_name) : nullptr;
  return (n && *n) ? std::string(n) : "";
}

std::string Tls::parse_client_hello_sni(const unsigned char* p, size_t n) {
  if (!p || n < 43) return "";
  if (p[0] != 0x16) return "";
  size_t rec_len = ((size_t)p[3] << 8) | p[4];
  if (n < 5 + rec_len) {
    // 记录不完整，仍尝试按现有长度解析
  }
  size_t end = n;
  size_t i = 5;
  if (i + 4 > end || p[i] != 0x01) return "";
  i += 4;  // handshake type + length
  if (i + 2 + 32 > end) return "";
  i += 2 + 32;  // version + random
  if (i + 1 > end) return "";
  size_t sid = p[i++];
  if (i + sid > end) return "";
  i += sid;
  if (i + 2 > end) return "";
  size_t cs = ((size_t)p[i] << 8) | p[i + 1];
  i += 2;
  if (i + cs > end) return "";
  i += cs;
  if (i + 1 > end) return "";
  size_t comp = p[i++];
  if (i + comp > end) return "";
  i += comp;
  if (i + 2 > end) return "";
  size_t ext_total = ((size_t)p[i] << 8) | p[i + 1];
  i += 2;
  size_t ext_end = std::min(end, i + ext_total);
  while (i + 4 <= ext_end) {
    unsigned int type = ((unsigned int)p[i] << 8) | p[i + 1];
    size_t len = ((size_t)p[i + 2] << 8) | p[i + 3];
    i += 4;
    if (i + len > ext_end) break;
    if (type == 0 && len >= 5) {
      size_t j = i;
      size_t list_len = ((size_t)p[j] << 8) | p[j + 1];
      j += 2;
      size_t stop = std::min(i + len, j + list_len);
      while (j + 3 <= stop) {
        unsigned int ntype = p[j];
        size_t nlen = ((size_t)p[j + 1] << 8) | p[j + 2];
        j += 3;
        if (j + nlen > stop) break;
        if (ntype == 0 && nlen > 0) return std::string((const char*)p + j, nlen);
        j += nlen;
      }
    }
    i += len;
  }
  return "";
}

bool tls_pipe_init(TlsPipe& p, SSL_CTX* ctx, bool server_side, std::string& err) {
  p.ssl = SSL_new(ctx);
  p.rbio = BIO_new(BIO_s_mem());
  p.wbio = BIO_new(BIO_s_mem());
  if (!p.ssl || !p.rbio || !p.wbio) {
    err = "创建 TLS 会话失败: " + openssl_err();
    tls_pipe_free(p);
    return false;
  }
  BIO_set_mem_eof_return(p.rbio, -1);
  SSL_set_bio(p.ssl, p.rbio, p.wbio);
  SSL_set_mode(p.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  if (server_side)
    SSL_set_accept_state(p.ssl);
  else
    SSL_set_connect_state(p.ssl);
  return true;
}

void tls_pipe_drain(TlsPipe& p, std::string& out) {
  if (!p.wbio) return;
  char buf[8192];
  int n;
  while ((n = BIO_read(p.wbio, buf, (int)sizeof buf)) > 0) out.append(buf, (size_t)n);
}

bool tls_pipe_handshake(TlsPipe& p, int fd, std::string& err) {
  for (int iter = 0; iter < 10000; ++iter) {
    ERR_clear_error();
    int rc = SSL_do_handshake(p.ssl);
    std::string out;
    tls_pipe_drain(p, out);
    if (!out.empty() && !send_all_blocking(fd, out.data(), out.size())) {
      err = "发送握手数据失败";
      return false;
    }
    if (rc == 1) return true;
    int e = SSL_get_error(p.ssl, rc);
    if (e == SSL_ERROR_WANT_READ) {
      char buf[16384];
      ssize_t n = recv(fd, buf, sizeof buf, 0);
      if (n <= 0) {
        err = n == 0 ? "对端关闭连接" : std::string("读取握手数据失败: ") + strerror(errno);
        return false;
      }
      BIO_write(p.rbio, buf, (int)n);
    } else if (e == SSL_ERROR_WANT_WRITE) {
      continue;
    } else {
      err = openssl_err();
      return false;
    }
  }
  err = "握手迭代超限";
  return false;
}

void tls_pipe_free(TlsPipe& p) {
  if (p.ssl) SSL_free(p.ssl);  // 同时释放 rbio/wbio
  p.ssl = nullptr;
  p.rbio = nullptr;
  p.wbio = nullptr;
}

}  // namespace shijima
