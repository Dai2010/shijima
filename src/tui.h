#pragma once
#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "filter.h"
#include "log.h"
#include "proxy.h"

namespace shijima {

// 本地 TUI：实时统计、最近记录、规则列表、可点击按钮。
// 支持 SGR 鼠标（按下即触发），键盘命令同时保留。
class Tui {
 public:
  struct View {
    std::string listen;
    std::string mode;
    std::string out_file;
  };

  Tui(Stats& st, Proxy& proxy, Filter& filter, View view);
  ~Tui();

  void start();
  void stop();
  void push(const Record& r);

 private:
  enum class Act { None, Allow, Deny, Clear, Quit, PickHost, RemoveRule };
  struct Region {
    int row = 0;
    int col_start = 0;
    int col_end = 0;
    Act act = Act::None;
    std::string payload;
    bool allow = false;
  };

  void loop();
  void render();
  void feed_input(const char* data, size_t n);
  void handle_escape(const std::string& seq);
  void on_click(int x, int y);
  void submit();
  void append_char(char c);
  void backspace();
  void set_message(const std::string& m);
  std::string current_input();

  Stats& st_;
  Proxy& proxy_;
  Filter& filter_;
  View view_;
  std::mutex mtx_;
  std::deque<Record> recent_;
  std::string input_;
  std::string message_;
  std::string pending_;
  std::vector<Region> regions_;
  std::atomic<bool> running_{false};
  std::thread thread_;
  bool active_ = false;
};

}  // namespace shijima
