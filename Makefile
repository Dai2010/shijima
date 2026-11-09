CXX      ?= c++
CXXFLAGS ?= -O2 -g -std=c++17 -Wall -Wextra -Wno-deprecated-declarations
CPPFLAGS += -D_GNU_SOURCE
LDLIBS   += -lssl -lcrypto -lpthread
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

SRC := src/main.cpp src/proxy.cpp src/http.cpp src/tls.cpp src/log.cpp src/util.cpp \
       src/filter.cpp src/tui.cpp
OBJ := $(SRC:.cpp=.o)

shijima: $(OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJ) $(LDLIBS)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c -o $@ $<

install: shijima
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 shijima $(DESTDIR)$(BINDIR)/shijima

check: shijima
	sh test/smoke.sh

clean:
	rm -f $(OBJ) shijima

.PHONY: install check clean
