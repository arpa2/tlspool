
TARGETS_OFFLINE = valexprun testvalexp
TARGETS = $(TARGETS_OFFLINE) onlinecheck testonline

OBJS = *.o

CFLAGS += -pthread -I ../include

# Hey... this is testing code, so c'mon let's DEBUG
CFLAGS += -DDEBUG

LDFLAGS =

LIBS = 

PREFIX = /usr/local

valexprun_CFLAGS = -ggdb3
valexprun_LIBS =

VALEXP_TESTS = $(shell cd data-valexp-in ; ls -1)

GNUTLS_CFLAGS = $(shell $(PKG_CONFIG) --cflags gnutls)
GNUTLS_LIBS   = $(shell $(PKG_CONFIG) --libs   gnutls)

P11KIT_CFLAGS = $(shell pkg-config --cflags p11-kit-1)
P11KIT_LIBS   = $(shell pkg-config --libs   p11-kit-1)

BDB_CFLAGS = 
BDB_LDFLAGS = -ldb

QUICKDER_CFLAGS = $(shell pkg-config --cflags quick-der) -ggdb3
QUICKDER_LIBS   = $(shell pkg-config --libs   quick-der)

all: $(TARGETS)

valexprun: valexprun.c ../src/validate.c
	gcc $(CFLAGS) $(valexprun_CFLAGS) -o "$@" "$<" $(valexprun_LIBS)

testvalexp: valexprun
	@ mkdir -p 'data-valexp-out'
	@ $(foreach test,$(VALEXP_TESTS),./valexprun $$(cat 'data-valexp-in/$(test)') > 'data-valexp-out/$(test)' && ) echo 'All validation expression test output was generated'
	@ echo -n '[ #FINAL == #SIGNAL ] test: '
	[ $(shell grep ^FINAL data-valexp-out/* | wc -l) -eq $(shell grep ^SIGNAL data-valexp-out/* | wc -l) ]
	@ echo -n '[ #Starting == #Stopping ] test: '
	[ $(shell grep ^Starting data-valexp-out/* | wc -l) -eq $(shell grep ^Stopping data-valexp-out/* | wc -l) ]
	@ git diff --stat --exit-code data-valexp-out
	@ git ls-files --error-unmatch data-valexp-in/* >/dev/null
	@ git ls-files --error-unmatch data-valexp-out/* >/dev/null
	@ echo All validation expression tests succeeded

onlinecheck: onlinecheck.c ../src/online.c ../src/pgp.c
	gcc $(CFLAGS) $(GNUTLS_CFLAGS) $(QUICKDER_CFLAGS) -o "$@" "$<" ../src/pgp.c -lunbound -lldns -lldap $(GNUTLS_LIBS) $(QUICKDER_LIBS)

testonline: onlinecheck
	./onlinecheck | tee | grep -v 'UNEXPECTED OUTPUT FAILURE'

clean:
	rm -f $(OBJS) $(TARGETS)
	rm -f valexp/*.gen

install:

uninstall:

