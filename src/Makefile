TARGETS = tlspool$(EXE)

OBJS = daemon.o config.o manage.o service.o cache.o pinentry.o lidentry.o \
	starttls.o donai.o remote.o error.o ctlkey.o validate.o

CFLAGS += -pthread -I ../include -std=gnu11
CFLAGS += $(GNUTLS_CFLAGS) $(P11KIT_CFLAGS) $(BDB_CFLAGS) $(TASN1_CFLAGS)

LDFLAGS += -std=gnu11

LIBS += $(GNUTLS_LIBS) $(P11KIT_LIBS) $(BDB_LIBS) $(TASN1_LIBS) -lpthread

ifdef WITH_SYSTEMD
CFLAGS += -DHAVE_SYSTEMD
LIBS   += -lsystemd-daemon
endif

GNUTLS_CFLAGS = $(shell $(PKG_CONFIG) --cflags gnutls)
GNUTLS_LIBS   = $(shell $(PKG_CONFIG) --libs   gnutls)
P11KIT_CFLAGS = $(shell $(PKG_CONFIG) --cflags p11-kit-1)
P11KIT_LIBS   = $(shell $(PKG_CONFIG) --libs   p11-kit-1)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -DATTRIBUTE_UNUSED="" -I ../include/windows
OBJS += windows/syslog.o windows/windows.o windows/getopt.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
EXE = .exe
endif

ifndef PKG_CONFIG
PKG_CONFIG=pkg-config
endif

ifndef SBIN
SBIN=sbin
endif

BDB_CFLAGS = 
ifdef WINVER
BDB_LIBS   = -ldb-6.1
else
BDB_LIBS   = -ldb
endif
TASN1_CFLAGS = $(shell $(PKG_CONFIG) --cflags libtasn1)
TASN1_LIBS   = $(shell $(PKG_CONFIG) --libs   libtasn1)

all: $(TARGETS)

tlspool$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o "$@" $(OBJS) $(LIBS)

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) $(TARGETS)

anew: clean all

install: all
	install $(TARGETS) "$(DESTDIR)$(PREFIX)/$(SBIN)/"

uninstall:
	@$(foreach t,$(TARGETS),rm -f '$(DESTDIR)$(PREFIX)/$(SBIN)/$t' && ) echo Removed TLS Pool daemon

