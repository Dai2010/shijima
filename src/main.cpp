#include <signal.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "filter.h"
#include "log.h"
#include "proxy.h"
#include "tls.h"
#include "tui.h"
#include "util.h"

using namespace shijima;

namespace {

void usage(FILE* out) {
  fprintf(out,
          "shijima 0.1.0 — 本地 HTTPS 抓包代理\n"
          "\n"
          "用法: shijima [选项]\n"
          "\n"
          "  -p, --port N          监听端口（默认 8899；被占用时自动顺延，0 = 随机）\n"
          "  -b, --bind ADDR       监听地址（默认 127.0.0.1）\n"
          "      --strict-port     端口被占用时直接失败\n"
          "  -o, --out PATH        抓包数据文件（默认 ./shijima-capture.json）\n"
          "  -f, --format FMT      json | jsonl | xml（默认 json）\n"
          "      --no-file         不写抓包文件\n"
          "      --no-console      不往终端打印抓包记录\n"
          "  -t, --tunnel          只做隧道，不解密 HTTPS（不需要 CA）\n"
          "  -k, --insecure        不校验上游证书\n"
          "      --ca-dir DIR      CA 证书存放目录\n"
          "      --print-ca        打印 CA 证书路径与指纹后退出\n"
          "      --deny PATTERN    拦截匹配的主机/IP，可逗号分隔或重复书写\n"
          "      --allow PATTERN   仅放行匹配的主机/IP（存在则默认拒绝）\n"
          "      --rules FILE      额外加载规则文件（YAML/逐行）\n"
          "      --rules-file PATH 指定规则库路径（默认 ~/.config/shijima/rules.yaml）\n"
          "      --allow-remote    允许绑定非回环地址（默认只监听本机）\n"
          "      --tui             启动本地 TUI（实时统计与规则编辑）\n"
          "      --body-limit N    每个报文保留的正文预览字节数（默认 2048）\n"
          "      --max-conn N      最大并发连接（默认 48）\n"
          "      --idle-timeout S  空闲超时秒数（默认 300）\n"
          "      --max-file SIZE   单个抓包文件上限，如 32M（默认 32M）\n"
          "  -h, --help            显示帮助\n"
          "  -v, --version         显示版本\n");
}

uint64_t parse_size(const std::string& s) {
  if (s.empty()) return 0;
  char* end = nullptr;
  unsigned long long v = strtoull(s.c_str(), &end, 10);
  if (end && (*end == 'k' || *end == 'K'))
    v *= 1024ull;
  else if (end && (*end == 'm' || *end == 'M'))
    v *= 1024ull * 1024;
  else if (end && (*end == 'g' || *end == 'G'))
    v *= 1024ull * 1024 * 1024;
  return v;
}

void print_summary(const Options& opt, Stats& st, Logger& log, CertStore* ca, uint16_t port) {
  uint64_t dur = 0;
  if (st.end_ms > st.start_ms) dur = st.end_ms - st.start_ms;
  printf("\n");
  printf("──────── shijima 抓包概要 ────────\n");
  printf("监听端口      %u\n", port);
  printf("运行时长      %s\n", fmt_duration(dur).c_str());
  printf("连接          %llu（MITM %llu / 隧道 %llu / 拦截 %llu / 错误 %llu）\n",
         (unsigned long long)st.conns.load(), (unsigned long long)st.mitm.load(),
         (unsigned long long)st.tunnels.load(), (unsigned long long)st.blocked.load(),
         (unsigned long long)st.errors.load());
  printf("请求 / 响应   %llu / %llu\n", (unsigned long long)st.requests.load(),
         (unsigned long long)st.responses.load());
  printf("上行 / 下行   %s / %s\n", fmt_size(st.up_bytes.load()).c_str(),
         fmt_size(st.down_bytes.load()).c_str());
  if (log.file_open())
    printf("抓包文件      %s（%llu 条，%s）\n", log.path().c_str(),
           (unsigned long long)log.records(), fmt_size(log.file_bytes()).c_str());
  if (ca) printf("CA 证书       %s\n", ca->ca_path().c_str());
  printf("──────────────────────────────────\n");
  (void)opt;
  fflush(stdout);
}

}  // namespace

int main(int argc, char** argv) {
  signal(SIGPIPE, SIG_IGN);

  Options opt;
  std::vector<std::string> deny_patterns;
  std::vector<std::string> allow_patterns;
  std::vector<std::string> rule_files;
  std::string rules_path = xdg_dir("XDG_CONFIG_HOME", ".config") + "/shijima/rules.yaml";
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](const char* name) -> std::string {
      if (i + 1 >= argc) {
        fprintf(stderr, "shijima: %s 缺少参数\n", name);
        exit(2);
      }
      return argv[++i];
    };
    if (a == "-h" || a == "--help") {
      usage(stdout);
      return 0;
    } else if (a == "-v" || a == "--version") {
      printf("shijima 0.1.0\n");
      return 0;
    } else if (a == "-p" || a == "--port") {
      int p = atoi(next("--port").c_str());
      if (p < 0 || p > 65535) {
        fprintf(stderr, "shijima: 端口范围 0-65535\n");
        return 2;
      }
      opt.port = (uint16_t)p;
    } else if (a == "-b" || a == "--bind") {
      opt.bind_addr = next("--bind");
    } else if (a == "--strict-port") {
      opt.strict_port = true;
    } else if (a == "-o" || a == "--out") {
      opt.log.path = next("--out");
    } else if (a == "-f" || a == "--format") {
      opt.log.format = next("--format");
      if (opt.log.format != "json" && opt.log.format != "jsonl" && opt.log.format != "xml") {
        fprintf(stderr, "shijima: --format 只支持 json / jsonl / xml\n");
        return 2;
      }
    } else if (a == "--no-file") {
      opt.log.file = false;
    } else if (a == "--no-console") {
      opt.log.console = false;
    } else if (a == "-t" || a == "--tunnel") {
      opt.mitm = false;
    } else if (a == "-k" || a == "--insecure") {
      opt.insecure = true;
    } else if (a == "--ca-dir") {
      opt.ca_dir = next("--ca-dir");
    } else if (a == "--print-ca") {
      opt.print_ca = true;
    } else if (a == "--deny") {
      deny_patterns.push_back(next("--deny"));
    } else if (a == "--allow") {
      allow_patterns.push_back(next("--allow"));
    } else if (a == "--rules") {
      rule_files.push_back(next("--rules"));
    } else if (a == "--rules-file") {
      rules_path = next("--rules-file");
    } else if (a == "--allow-remote") {
      opt.allow_remote = true;
    } else if (a == "--tui") {
      opt.tui = true;
    } else if (a == "--body-limit") {
      opt.body_limit = (size_t)parse_size(next("--body-limit"));
    } else if (a == "--max-conn") {
      opt.max_conn = atoi(next("--max-conn").c_str());
    } else if (a == "--idle-timeout") {
      opt.idle_timeout = atoi(next("--idle-timeout").c_str());
    } else if (a == "--max-file") {
      opt.log.max_file_bytes = parse_size(next("--max-file"));
    } else {
      fprintf(stderr, "shijima: 未知参数 %s（用 --help 查看用法）\n", a.c_str());
      return 2;
    }
  }

  if (opt.log.format.empty()) opt.log.format = "json";
  if (opt.log.path.empty())
    opt.log.path = opt.log.format == "xml" ? "./shijima-capture.xml"
                                           : (opt.log.format == "jsonl" ? "./shijima-capture.jsonl"
                                                                        : "./shijima-capture.json");
  if (opt.body_limit < 64) opt.body_limit = 64;
  if (opt.body_limit > 65536) opt.body_limit = 65536;
  if (opt.max_conn < 1) opt.max_conn = 1;
  if (opt.idle_timeout < 10) opt.idle_timeout = 10;
  if (opt.ca_dir.empty()) opt.ca_dir = xdg_dir("XDG_STATE_HOME", ".local/state") + "/shijima";

  std::string err;
  {
    std::string bind = to_lower(opt.bind_addr);
    bool local = bind == "localhost" || bind == "::1" || bind.rfind("127.", 0) == 0;
    if (!local && !opt.allow_remote) {
      fprintf(stderr,
              "shijima: 默认只监听本机回环地址；要绑定 %s 请显式加 --allow-remote\n",
              opt.bind_addr.c_str());
      return 2;
    }
  }

  Filter filter;
  if (file_exists(rules_path)) {
    if (!filter.load_file(rules_path, err)) {
      fprintf(stderr, "shijima: %s\n", err.c_str());
      return 2;
    }
  }
  for (const auto& item : deny_patterns)
    for (const auto& p : split_patterns(item)) filter.add(false, p);
  for (const auto& item : allow_patterns)
    for (const auto& p : split_patterns(item)) filter.add(true, p);
  for (const auto& file : rule_files) {
    if (!filter.load_file(file, err)) {
      fprintf(stderr, "shijima: %s\n", err.c_str());
      return 2;
    }
  }
  filter.set_store_path(rules_path);
  if (!file_exists(rules_path)) {
    if (!filter.save(rules_path, err))
      fprintf(stderr, "shijima: 警告: %s（规则只在本次运行内生效）\n", err.c_str());
  }
  opt.filter = &filter;
  if (opt.tui) opt.log.console = false;

  CertStore ca;
  if (opt.mitm || opt.print_ca) {
    if (!ca.init(opt.ca_dir, err)) {
      fprintf(stderr, "shijima: %s\n", err.c_str());
      return 1;
    }
  }
  if (opt.print_ca) {
    printf("%s\n", ca.ca_path().c_str());
    printf("SHA-256 %s\n", ca.ca_fingerprint().c_str());
    return 0;
  }

  if (!opt.log.console && !opt.log.file) {
    fprintf(stderr, "shijima: --no-console 与 --no-file 同时使用没有意义\n");
    return 2;
  }

  Logger log;
  if (!log.init(opt.log, err)) {
    fprintf(stderr, "shijima: %s\n", err.c_str());
    return 1;
  }

  Stats st;
  st.start_ms = mono_ms();
  Proxy proxy(opt, log, opt.mitm ? &ca : nullptr, st);
  if (!proxy.init_tls(err)) {
    fprintf(stderr, "shijima: %s\n", err.c_str());
    log.close();
    return 1;
  }

  std::unique_ptr<Tui> tui;
  if (opt.tui) {
    if (!isatty(STDIN_FILENO)) {
      fprintf(stderr, "shijima: --tui 需要交互终端，已回退为普通输出\n");
      opt.log.console = true;
    } else {
      Tui::View view;
      view.listen = opt.bind_addr + ":" +
                    (opt.port ? std::to_string(opt.port) : std::string("auto"));
      view.mode = opt.mitm ? (opt.insecure ? "MITM 不校验" : "MITM 解密") : "隧道";
      view.out_file = opt.log.file ? opt.log.path : "(未写文件)";
      tui.reset(new Tui(st, proxy, filter, view));
      log.set_sink([ptr = tui.get()](const Record& r) { ptr->push(r); });
      tui->start();
    }
  }

  int rc = proxy.run();
  st.end_ms = mono_ms();
  if (tui) tui->stop();

  {
    Record r;
    r.kind = "summary";
    r.time = now_iso_ms();
    char buf[256];
    snprintf(buf, sizeof buf,
             "conns=%llu requests=%llu responses=%llu blocked=%llu errors=%llu",
             (unsigned long long)st.conns.load(), (unsigned long long)st.requests.load(),
             (unsigned long long)st.responses.load(), (unsigned long long)st.blocked.load(),
             (unsigned long long)st.errors.load());
    r.note = buf;
    log.emit(r);
  }
  print_summary(opt, st, log, opt.mitm ? &ca : nullptr, proxy.bound_port());
  log.close();
  return rc;
}
