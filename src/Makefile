TARGETS = tlspool$(EXE)

OBJS = daemon.o config.o manage.o service.o cache.o pinentry.o lidentry.o \
	starttls.o donai.o remote.o error.o ctlkey.o \
	validate.o online.o pgp.o trust.o

CFLAGS += -pthread -I ../include -std=gnu11
CFLAGS += $(GNUTLS_CFLAGS) $(P11KIT_CFLAGS) $(BDB_CFLAGS) $(TASN1_CFLAGS) $(UNBOUND_CFLAGS) $(QUICKDER_CFLAGS)

LDFLAGS += -std=gnu11

LIBS = $(GNUTLS_LIBS) $(P11KIT_LIBS) $(BDB_LIBS) $(TASN1_LIBS) $(UNBOUND_LIBS) $(QUICKDER_LIBS)
LIBS += -lldns -lpthread

ifdef WITH_SYSTEMD
CFLAGS += -DHAVE_SYSTEMD
LIBS   += -lsystemd-daemon
endif

ifndef WITHOUT_KERBEROS
CFLAGS += -DHAVE_TLS_KDH $(KERBEROS_CFLAGS)
LIBS += $(KERBEROS_LIBS)
endif

GNUTLS_CFLAGS = $(shell $(PKG_CONFIG) --cflags gnutls)
GNUTLS_LIBS   = $(shell $(PKG_CONFIG) --libs   gnutls)
GNUTLS_CFLAGS += $(shell $(PKG_CONFIG) --cflags gnutls-dane)
GNUTLS_LIBS   += $(shell $(PKG_CONFIG) --libs   gnutls-dane)
P11KIT_CFLAGS = $(shell $(PKG_CONFIG) --cflags p11-kit-1)
P11KIT_LIBS   = $(shell $(PKG_CONFIG) --libs   p11-kit-1)
TASN1_CFLAGS = $(shell $(PKG_CONFIG) --cflags libtasn1)
TASN1_LIBS   = $(shell $(PKG_CONFIG) --libs   libtasn1)
#HOWTOUSE# UNBOUND_FLAGS = $(shell $(PKG_CONFIG) --cflags libunbound)
#HOWTOUSE# UNBOUND_LIBS  = $(shell $(PKG_CONFIG) --libs   libunbound)
QUICKDER_CFLAGS = $(shell $(PKG_CONFIG) --cflags quick-der)
QUICKDER_LIBS   = $(shell $(PKG_CONFIG) --libs   quick-der)
KERBEROS_CFLAGS = $(shell krb5-config --cflags)
KERBEROS_LIBS = $(shell krb5-config --libs)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -DATTRIBUTE_UNUSED="" -I ../include/windows
OBJS += windows/syslog.o windows/windows.o windows/getopt.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
EXE = .exe
endif

PKG_CONFIG ?= pkg-config

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -DATTRIBUTE_UNUSED="" -I ../include/windows
OBJS += windows/syslog.o windows/windows.o windows/getopt.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32 -lwldap32 -lunbound
EXE = .exe
else
LIBS += -lldap
endif

PKG_CONFIG ?= pkg-config

SBIN ?= sbin

BDB_CFLAGS = 
ifdef WINVER
BDB_LIBS   = -ldb-6.1
else
BDB_LIBS   = -ldb # this is the default
endif

TASN1_CFLAGS = $(shell pkg-config --cflags libtasn1)
TASN1_LIBS   = $(shell pkg-config --libs   libtasn1)
#HOWTOUSE# UNBOUND_FLAGS = $(shell pkg-config --cflags libunbound)
#HOWTOUSE# UNBOUBD_LIBS  = $(shell pkg-config --libs   libunbound)
QUICKDER_CFLAGS = $(shell pkg-config --cflags quick-der)
QUICKDER_LIBS = $(shell pkg-config --libs quick-der)
KERBEROS_CFLAGS = $(shell krb5-config --cflags)
KERBEROS_LIBS = $(shell krb5-config --libs)
# CFLAGS += -DHAVE_TLS_KDH

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

