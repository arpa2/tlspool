
TARGETS = testcli testsrv tlstunnel \
	pingpool lidsel pinentry \
	get_localid set_localid \
	get_disclose set_disclose \
	get_trust set_trust \
	pgp11_genkey \
	configvar

OBJS = *.o

CFLAGS += -pthread -I ../include

LDFLAGS =

LIBS = 

PREFIX = /usr/local

tlspool_LIB = ../lib/libtlspool.so
tlspool_LDFLAGS = -L ../lib -ltlspool

donai_CFLAGS = -DDONAI_ONLY_TEXTPROC
donai_SRC = ../src/donai.c

pgp11genkey_CFLAGS = $(P11KIT_CFLAGS)
pgp11genkey_LIBS = $(P11KIT_LIBS) -lcrypto

configvar_CFLAGS = 
configvar_LIBS = $(tlspool_LIB)

P11KIT_CFLAGS = $(shell pkg-config --cflags p11-kit-1)
P11KIT_LIBS   = $(shell pkg-config --libs   p11-kit-1)

BDB_CFLAGS = 
BDB_LDFLAGS = -ldb

all: $(TARGETS)

testcli: testcli.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)

testsrv: testsrv.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)

testpeer: testpeer.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)
	@echo '#'
	@echo '# You cannot use testpeer yet'
	@echo '#'

tlstunnel: tlstunnel.c tlstunnel-chat.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" tlstunnel.c tlstunnel-chat.c $(tlspool_LDFLAGS)

pingpool: pingpool.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)

lidsel: lidsel.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)

pinentry: pinentry.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS)

get_localid: get_localid.c
	gcc -std=gnu11 $(CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

set_localid: set_localid.c
	gcc -std=gnu11 $(CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

get_disclose: get_disclose.c $(donai_SRC)
	gcc -std=gnu11 $(CFLAGS) $(donai_CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(donai_SRC) $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

set_disclose: set_disclose.c
	gcc -std=gnu11 $(CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

get_trust: get_trust.c $(donai_SRC)
	gcc -std=gnu11 $(CFLAGS) $(donai_CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(donai_SRC) $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

set_trust: set_trust.c
	gcc -std=gnu11 $(CFLAGS) $(BDB_CFLAGS) -o "$@" "$<" $(tlspool_LDFLAGS) $(BDB_LDFLAGS)

pgp11_genkey: pgp11_genkey.c
	gcc -std=gnu11 $(CFLAGS) $(pgp11genkey_CFLAGS) -o "$@" "$<" $(pgp11genkey_LIBS)

configvar: configvar.c $(tlspool_LIB)
	gcc -std=gnu11 $(CFLAGS) $(configvar_CFLAGS) -o "$@" "$<" $(configvar_LIBS)

$(tlspool_LIB):
	$(MAKE) -C ../lib `basename $(tlspool_LIB)`

.c.o:
	gcc -std=gnu11 -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) $(TARGETS)

anew: clean all

install: all
	install $(TARGETS) "$(DESTDIR)$(PREFIX)/sbin/"

uninstall:
	@$(foreach t,$(TARGETS),rm -f '$(DESTDIR)$(PREFIX)/sbin/$t' && ) echo Removed TLS Pool utilities

