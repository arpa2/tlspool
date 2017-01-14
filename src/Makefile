TARGETS = tlspool$(EXE)

OBJS = daemon.o config.o manage.o service.o cache.o pinentry.o lidentry.o \
	starttls.o donai.o remote.o error.o ctlkey.o \
	validate.o online.o pgp.o trust.o

CFLAGS += -pthread -I ../include -std=gnu11
CFLAGS += $(GNUTLS_CFLAGS) $(P11KIT_CFLAGS) $(BDB_CFLAGS) $(TASN1_CFLAGS) $(UNBOUND_CFLAGS) $(QUICKDER_CFLAGS) $(NIX_MAGIC_CFLAGS)

LDFLAGS += -std=gnu11

LIBS = $(GNUTLS_LIBS) $(P11KIT_LIBS) $(BDB_LIBS) $(TASN1_LIBS) $(UNBOUND_LIBS) $(QUICKDER_LIBS) $(NIX_MAGIC_LIBS)
LIBS += $(LDNS_LIBS) -lpthread

ifdef WITH_SYSTEMD
CFLAGS += -DHAVE_SYSTEMD
LIBS   += $(SYSTEMD_LIBS) 
endif

ifndef WITHOUT_KERBEROS
CFLAGS += -DHAVE_TLS_KDH $(KERBEROS_CFLAGS)
LIBS += $(KERBEROS_LIBS)
endif

ifdef DEBUG
CFLAGS += -g -O0
endif

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -DATTRIBUTE_UNUSED="" -I ../include/windows
OBJS += windows/syslog.o windows/windows.o windows/getopt.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
EXE = .exe
endif

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -DATTRIBUTE_UNUSED="" -I ../include/windows
OBJS += windows/syslog.o windows/windows.o windows/getopt.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32 -lwldap32 -lunbound
EXE = .exe
else
LIBS += $(LDAP_LIBS)
endif

SBIN ?= sbin

BDB_CFLAGS = 
ifdef WINVER
BDB_LIBS   = -ldb-6.1
endif

all: $(TARGETS)

tlspool$(EXE): $(OBJS)
	$(CC) $(LDFLAGS) -o "$@" $(OBJS) $(LIBS)

%.o: %.c
	$(CC) -c $(CFLAGS) -o "$@" "$<"

%.pre: %.c
	$(CC) -E $(CFLAGS) -o "$@" "$<"

.PHONY: clean
clean:
	rm -f $(OBJS) $(TARGETS)

anew: clean all

install: all
	install $(TARGETS) "$(DESTDIR)/$(PREFIX)/$(SBIN)/"

uninstall:
	@$(foreach t,$(TARGETS),rm -f '$(DESTDIR)/$(PREFIX)/$(SBIN)/$t' && ) echo Removed TLS Pool daemon

