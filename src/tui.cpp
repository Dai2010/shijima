#include "tui.h"

#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

#include "util.h"

namespace shijima {
namespace {

termios g_saved;
bool g_raw_set = false;

const char* kEnterScreen = "\033[?1049h\033[?25l\033[?1000h\033[?1006h";
const char* kLeaveScreen = "\033[?1000l\033[?1006l\033[?25h\033[?1049l";

void enter_raw() {
  if (!isatty(STDIN_FILENO)) return;
  if (tcgetattr(STDIN_FILENO, &g_saved) != 0) return;
  termios t = g_saved;
  t.c_lflag &= ~(unsigned)(ICANON | ECHO);
  t.c_cc[VMIN] = 1;
  t.c_cc[VTIME] = 0;
  if (tcsetattr(STDIN_FILENO, TCSANOW, &t) == 0) g_raw_set = true;
  fputs(kEnterScreen, stdout);
}

void leave_raw() {
  fputs(kLeaveScreen, stdout);
  if (g_raw_set) tcsetattr(STDIN_FILENO, TCSANOW, &g_saved);
  g_raw_set = false;
  fflush(stdout);
}

int term_width() {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) return ws.ws_col;
  return 48;
}

std::string rep(const char* glyph, int n) {
  std::string out;
  if (n <= 0) return out;
  for (int i = 0; i < n; ++i) out += glyph;
  return out;
}

std::string truncate_utf8(const std::string& s, size_t w) {
  if (s.size() <= w) return s;
  if (w <= 1) return s.substr(0, w);
  return s.substr(0, w - 1) + "…";
}

}  // namespace

Tui::Tui(Stats& st, Proxy& proxy, Filter& filter, View view)
    : st_(st), proxy_(proxy), filter_(filter), view_(std::move(view)) {
  active_ = isatty(STDIN_FILENO) && isatty(STDOUT_FILENO);
}

Tui::~Tui() { stop(); }

void Tui::start() {
  if (!active_ || running_.load()) return;
  running_ = true;
  thread_ = std::thread([this] { loop(); });
}

void Tui::stop() {
  if (!running_.exchange(false)) return;
  if (thread_.joinable()) thread_.join();
  leave_raw();
}

void Tui::push(const Record& r) {
  std::lock_guard<std::mutex> lock(mtx_);
  recent_.push_back(r);
  while (recent_.size() > 6) recent_.pop_front();
}

void Tui::set_message(const std::string& m) {
  std::lock_guard<std::mutex> lock(mtx_);
  message_ = m;
}

std::string Tui::current_input() {
  std::lock_guard<std::mutex> lock(mtx_);
  return input_;
}

void Tui::append_char(char c) {
  std::lock_guard<std::mutex> lock(mtx_);
  if (input_.size() < 96) input_.push_back(c);
}

void Tui::backspace() {
  std::lock_guard<std::mutex> lock(mtx_);
  if (!input_.empty()) input_.pop_back();
}

void Tui::submit() {
  std::string cmd = trim_copy(current_input());
  {
    std::lock_guard<std::mutex> lock(mtx_);
    input_.clear();
  }
  if (cmd.empty()) return;
  if (cmd == "q" || cmd == "quit" || cmd == "exit") {
    proxy_.stop();
    return;
  }
  if (cmd == "c" || cmd == "clear") {
    filter_.clear();
    set_message("已清空全部规则");
    return;
  }
  bool allow = false;
  if (cmd.rfind("a ", 0) == 0 || cmd[0] == '+') {
    allow = true;
    cmd = trim_copy(cmd.substr(cmd[0] == '+' ? 1 : 2));
  } else if (cmd.rfind("d ", 0) == 0 || cmd[0] == '-') {
    cmd = trim_copy(cmd.substr(cmd[0] == '-' ? 1 : 2));
  }
  if (cmd.empty()) {
    set_message("缺少通配符，例如: *.ads.example 或 d *ads*");
    return;
  }
  filter_.add(allow, cmd);
  set_message((allow ? "已允许 " : "已拦截 ") + cmd);
}

void Tui::handle_escape(const std::string& seq) {
  if (seq.size() < 6 || seq.compare(0, 3, "\033[<") != 0) return;
  int b = -1, x = 0, y = 0;
  char tail = 0;
  if (sscanf(seq.c_str() + 3, "%d;%d;%d%c", &b, &x, &y, &tail) != 4) return;
  if (tail != 'M') return;
  if ((b & 3) != 0) return;  // 仅左键
  if (b & 32) return;        // 拖动
  on_click(x, y);
}

void Tui::on_click(int x, int y) {
  Region hit;
  {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& r : regions_) {
      if (r.row == y && x >= r.col_start && x <= r.col_end) {
        hit = r;
        break;
      }
    }
  }
  switch (hit.act) {
    case Act::Allow:
    case Act::Deny: {
      std::string pat = trim_copy(current_input());
      if (pat.empty()) {
        set_message("先在输入行填通配符，或点选一个域名");
        return;
      }
      {
        std::lock_guard<std::mutex> lock(mtx_);
        input_.clear();
      }
      bool allow = hit.act == Act::Allow;
      filter_.add(allow, pat);
      set_message((allow ? "已允许 " : "已拦截 ") + pat);
      break;
    }
    case Act::Clear:
      filter_.clear();
      set_message("已清空全部规则");
      break;
    case Act::Quit:
      proxy_.stop();
      break;
    case Act::PickHost: {
      std::lock_guard<std::mutex> lock(mtx_);
      input_ = hit.payload;
      message_ = "已选中 " + hit.payload + "，点 [允许] 或 [拦截]";
      break;
    }
    case Act::RemoveRule:
      filter_.remove_rule(hit.allow, hit.payload);
      set_message("已删除规则 " + hit.payload);
      break;
    case Act::None:
      break;
  }
}

void Tui::feed_input(const char* data, size_t n) {
  pending_.append(data, n);
  size_t i = 0;
  while (i < pending_.size()) {
    unsigned char c = (unsigned char)pending_[i];
    if (c == 0x1b) {
      if (pending_.size() - i < 3) break;
      if (pending_[i + 1] != '[') {
        i += 1;
        continue;
      }
      size_t j = i + 2;
      while (j < pending_.size() && pending_[j] != 'M' && pending_[j] != 'm') ++j;
      if (j >= pending_.size()) break;
      handle_escape(pending_.substr(i, j - i + 1));
      i = j + 1;
      continue;
    }
    if (c == '\r' || c == '\n') {
      submit();
      ++i;
      continue;
    }
    if (c == 127 || c == 8) {
      backspace();
      ++i;
      continue;
    }
    if (c == 3) {
      proxy_.stop();
      ++i;
      continue;
    }
    if (c >= 0x20) {
      append_char((char)c);
      ++i;
      continue;
    }
    ++i;
  }
  pending_.erase(0, i);
}

void Tui::loop() {
  enter_raw();
  auto last_render = std::chrono::steady_clock::now() - std::chrono::seconds(1);
  while (running_.load() && !proxy_stopped()) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    int rc = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
    if (rc > 0 && FD_ISSET(STDIN_FILENO, &rfds)) {
      char buf[256];
      ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
      if (n > 0) feed_input(buf, (size_t)n);
    }
    auto now = std::chrono::steady_clock::now();
    if (now - last_render > std::chrono::milliseconds(350)) {
      render();
      last_render = now;
    }
  }
}

void Tui::render() {
  int w = term_width();
  if (w < 30) w = 30;
  const int inner = w - 4;
  if (inner < 20) return;

  const bool color = true;
  const char* reset = "\033[0m";
  const char* bold = "\033[1m";
  const char* dim = "\033[2m";
  const char* cyan = "\033[36m";
  const char* green = "\033[32m";
  const char* yellow = "\033[33m";
  const char* red = "\033[31m";
  const char* magenta = "\033[35m";
  const char* inverse = "\033[7m";

  std::vector<std::string> lines;
  std::vector<Region> regions;
  int row = 0;

  auto push_raw = [&](const std::string& s) {
    lines.push_back(s);
    ++row;
  };
  auto push_line = [&](const std::string& content) {
    std::string vis = truncate_utf8(content, (size_t)inner);
    std::string pad((size_t)inner - vis.size(), ' ');
    lines.push_back(std::string("│ ") + vis + pad + " │");
    ++row;
    return row;
  };
  auto push_blank = [&]() { push_line(""); };

  // 顶部标题
  {
    std::string title = " shijima ";
    int dashes = w - 2 - (int)title.size();
    if (dashes < 1) dashes = 1;
    push_raw(std::string("╭─") + bold + cyan + title + reset + rep("─", dashes) + "╮");
  }
  push_line(std::string(bold) + view_.listen + reset + "   " + view_.mode);
  push_blank();

  // 统计
  {
    char b[256];
    snprintf(b, sizeof b, "连接 %llu   MITM %llu   隧道 %llu   拦截 %llu   错误 %llu",
             (unsigned long long)st_.conns.load(), (unsigned long long)st_.mitm.load(),
             (unsigned long long)st_.tunnels.load(), (unsigned long long)st_.blocked.load(),
             (unsigned long long)st_.errors.load());
    push_line(b);
    snprintf(b, sizeof b, "请求 %llu / 响应 %llu   ↑%s ↓%s",
             (unsigned long long)st_.requests.load(),
             (unsigned long long)st_.responses.load(), fmt_size(st_.up_bytes.load()).c_str(),
             fmt_size(st_.down_bytes.load()).c_str());
    push_line(b);
  }
  {
    std::vector<std::pair<std::string, uint64_t>> hosts;
    proxy_.top_hosts(hosts, 3);
    std::string h = dim + std::string("热点 ") + reset;
    for (size_t i = 0; i < hosts.size(); ++i) {
      if (i) h += std::string(dim) + "  " + reset;
      h += hosts[i].first + "(" + std::to_string(hosts[i].second) + ")";
    }
    if (hosts.empty()) h += dim + std::string("暂无") + reset;
    push_line(h);
  }

  // 最近记录
  {
    std::string label = " 最近 ";
    int dashes = w - 2 - (int)label.size() - 1;
    if (dashes < 1) dashes = 1;
    push_raw(std::string("├─") + dim + label + reset + rep("─", dashes) + "┤");
  }
  {
    std::lock_guard<std::mutex> lock(mtx_);
    int shown = 0;
    for (auto it = recent_.rbegin(); it != recent_.rend() && shown < 5; ++it, ++shown) {
      const Record& r = *it;
      std::string ts = r.time.size() >= 19 ? r.time.substr(11, 8) : "--:--:--";
      std::string line = ts + " ";
      const char* col = reset;
      if (r.kind == "request") {
        line += std::string(cyan) + "REQ" + reset + " " + r.method + " " + r.host + r.target;
      } else if (r.kind == "response") {
        col = green;
        line += std::string(col) + "RES" + reset + " " + std::to_string(r.status) + " " +
                fmt_size(r.size);
      } else if (r.kind == "blocked") {
        line += std::string(red) + "BLK" + reset + " " + r.host;
      } else if (r.kind == "connection") {
        line += std::string(magenta) + "CON" + reset + " " + r.host;
      } else if (r.kind == "tunnel") {
        line += std::string(magenta) + "TUN" + reset + " " + r.host + " " + r.note;
      } else if (r.kind == "error") {
        line += std::string(red) + "ERR" + reset + " " + r.note;
      } else {
        line += r.kind + " " + r.note;
      }
      int rr = push_line(line);
      if (!r.host.empty()) {
        Region reg;
        reg.row = rr;
        reg.col_start = 3;
        reg.col_end = w - 2;
        reg.act = Act::PickHost;
        reg.payload = r.host;
        regions.push_back(reg);
      }
    }
    if (shown == 0) push_line(dim + std::string("等待流量…") + reset);
  }

  // 规则
  std::vector<std::pair<bool, std::string>> rules;
  {
    std::string label = " 规则 ";
    int dashes = w - 2 - (int)label.size() - 1;
    if (dashes < 1) dashes = 1;
    push_raw(std::string("├─") + dim + label + reset + rep("─", dashes) + "┤");
  }
  rules = filter_.snapshot();
  {
    int shown = 0;
    for (auto it = rules.rbegin(); it != rules.rend() && shown < 4; ++it, ++shown) {
      std::string line = std::string(it->first ? green : red) + (it->first ? "+ " : "- ") +
                         reset + it->second;
      int rr = push_line(line);
      Region reg;
      reg.row = rr;
      reg.col_start = 3;
      reg.col_end = w - 2;
      reg.act = Act::RemoveRule;
      reg.payload = it->second;
      reg.allow = it->first;
      regions.push_back(reg);
    }
    if (rules.empty()) push_line(dim + std::string("（无，默认全部放行）") + reset);
    else if (rules.size() > 4)
      push_line(dim + std::string("还有 ") + std::to_string(rules.size() - 4) + " 条…" + reset);
  }

  // 按钮
  {
    std::string sep = rep("─", w - 2);
    push_raw(std::string("├") + sep + "┤");
  }
  {
    std::string buttons = std::string(inverse) + " 允许 " + reset + " " +
                          inverse + " 拦截 " + reset + " " + inverse + " 清空 " + reset +
                          " " + inverse + " 退出 " + reset;
    int rr = push_line(buttons);
    struct Btn { int offset; int len; Act act; };
    const Btn btns[] = {{0, 6, Act::Allow}, {7, 6, Act::Deny}, {14, 6, Act::Clear}, {21, 6, Act::Quit}};
    for (const auto& b : btns) {
      Region reg;
      reg.row = rr;
      reg.col_start = 3 + b.offset;
      reg.col_end = 3 + b.offset + b.len - 1;
      reg.act = b.act;
      regions.push_back(reg);
    }
  }
  {
    std::string input = current_input();
    std::string line = bold + std::string("> ") + reset + input + "_";
    push_line(line);
  }
  {
    std::string msg;
    {
      std::lock_guard<std::mutex> lock(mtx_);
      msg = message_;
    }
    if (msg.empty())
      msg = dim + std::string("点域名选中，点规则删除；回车提交，q 退出") + reset;
    push_line(msg);
  }

  {
    int dashes = w - 2;
    if (dashes < 1) dashes = 1;
    push_raw(std::string("╰") + rep("─", dashes) + "╯");
  }

  {
    std::lock_guard<std::mutex> lock(mtx_);
    regions_ = regions;
  }

  std::string out = "\033[H";
  for (const auto& l : lines) {
    out += l;
    out += "\033[K\r\n";
  }
  fwrite(out.data(), 1, out.size(), stdout);
  fflush(stdout);
}

}  // namespace shijima
