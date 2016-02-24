TARGETS = tlspool

OBJS = daemon.o config.o manage.o service.o cache.o pinentry.o lidentry.o \
	starttls.o donai.o remote.o error.o ctlkey.o validate.o

CFLAGS += -pthread -I ../include
CFLAGS += $(GNUTLS_CFLAGS) $(P11KIT_CFLAGS) $(BDB_CFLAGS) $(TASN1_CFLAGS)

LDFLAGS =

LIBS = $(GNUTLS_LIBS) $(P11KIT_LIBS) $(BDB_LIBS) $(TASN1_LIBS) -lpthread

GNUTLS_CFLAGS = $(shell pkg-config --cflags gnutls)
GNUTLS_LIBS   = $(shell pkg-config --libs   gnutls)
P11KIT_CFLAGS = $(shell pkg-config --cflags p11-kit-1)
P11KIT_LIBS   = $(shell pkg-config --libs   p11-kit-1)
BDB_CFLAGS = 
BDB_LIBS   = -ldb
TASN1_CFLAGS = $(shell pkg-config --cflags libtasn1)
TASN1_LIBS   = $(shell pkg-config --libs   libtasn1)

all: $(TARGETS)

tlspool: $(OBJS)
	gcc $(LDFLAGS) -o "$@" $(OBJS) $(LIBS)

.c.o:
	gcc -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) $(TARGETS)

install: all
	install $(TARGETS) "$(PREFIX)/sbin/"

uninstall:
	@($foreach t,$(TARGETS),rm -f '$(PREFIX)/sbin/$t' && ) echo Removed TLS Pool daemon

