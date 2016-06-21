ifdef WINVER
TARGETS = tlspool.dll
else
TARGETS = tlspool.so
endif

CFLAGS += -fPIC -I . -I ../include -std=gnu11

LDFLAGS += -std=gnu11

LIBS += -ldb

PREFIX ?= /usr/local

tlspool_OBJS = api.o parse.o connect.o

OBJS = $(tlspool_OBJS)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
tlspool_OBJS += ../lib/windows/syslog.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
endif

all: $(TARGETS)

tlspool.so: $(tlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(tlspool_OBJS) $(LIBS)

tlspool.dll: $(tlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(tlspool_OBJS) $(LIBS)

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)

anew: clean all

install: all
ifdef WINVER
	mkdir -p "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	install tlspool.dll "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
else	
	mkdir -p "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	install tlspool.so "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	@echo #
	@echo # Python libraries not yet installed
	@echo #
	@echo # You may need to run ldconfig to update the ld.so cache
	@echo #
endif

uninstall:
ifdef WINVER
	rm -f "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback/tlspool.dll"
else
	rm -f "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback/tlspool.so"
	@echo #
	@echo # Python libraries not yet removed
	@echo #
endif
