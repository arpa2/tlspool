ifdef WINVER
TARGETS = pulleyback_tlspool.dll
else
TARGETS = pulleyback_tlspool.so
endif

CFLAGS += -ggdb3 -O0
CFLAGS += -fPIC -I . -I ../include -std=gnu11

LDFLAGS += -std=gnu11

BDB_CFLAGS = 
ifdef WINVER
BDB_LIBS   = -ldb-6.1
else
BDB_LIBS   = -ldb
endif

PREFIX ?= /usr/local

pulleyback_tlspool_OBJS = api.o parse.o connect.o update.o

OBJS = $(pulleyback_tlspool_OBJS)

PKG_CONFIG ?= pkg-config

QUICKDER_CFLAGS = $(shell $(PKG_CONFIG) --cflags quick-der)
QUICKDER_LIBS = $(shell $(PKG_CONFIG) --libs quick-der)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
pulleyback_tlspool_OBJS += ../lib/windows/syslog.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
endif

all: $(TARGETS)

pulleyback_tlspool.so: $(pulleyback_tlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(pulleyback_tlspool_OBJS) $(BDB_LIBS) $(QUICKDER_LIBS)

pulleyback_tlspool.dll: $(pulleyback_tlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(pulleyback_tlspool_OBJS) $(BDB_LIBS) $(QUICKDER_LIBS)

.c.o:
	$(CC) -c $(CFLAGS) $(BDB_CFLAGS) $(QUICKDER_CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)

anew: clean all

install: all
ifdef WINVER
	mkdir -p "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	install pulleyback_tlspool.dll "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
else	
	mkdir -p "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	install pulleyback_tlspool.so "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback"
	@echo '#'
	@echo '# Python libraries not yet installed'
	@echo '#'
	@echo '# You may need to run ldconfig to update the ld.so cache'
	@echo '#'
endif

uninstall:
ifdef WINVER
	rm -f "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback/pulleyback_tlspool.dll"
else
	rm -f "$(DESTDIR)$(PREFIX)/share/steamworks/pulleyback/pulleyback_tlspool.so"
	@echo '#'
	@echo '# Python libraries not yet removed'
	@echo '#'
endif
