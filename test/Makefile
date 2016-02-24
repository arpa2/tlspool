
TARGETS = valexprun testvalexp

OBJS = *.o

CFLAGS += -pthread -I ../include

LDFLAGS =

LIBS = 

PREFIX = /usr/local

valexprun_CFLAGS = -ggdb3
valexprun_LIBS =

VALEXP_TESTS = $(shell ls -1 valexp/*.in)

P11KIT_CFLAGS = $(shell pkg-config --cflags p11-kit-1)
P11KIT_LIBS   = $(shell pkg-config --libs   p11-kit-1)

BDB_CFLAGS = 
BDB_LDFLAGS = -ldb

all: $(TARGETS)

valexprun: valexprun.c ../src/validate.c
	gcc $(CFLAGS) $(valexprun_CFLAGS) -o "$@" "$<" $(valexprun_LIBS)

testvalexp: valexprun
	@ $(foreach test,$(VALEXP_TESTS),./valexprun $$(cat '$(test)') > '$(test:.in=.gen)' && ) echo 'All validation expression test output was generated'
	@ $(foreach test,$(VALEXP_TESTS),diff -q '$(test:.in=.gen)' '$(test:.in=.good)' && ) echo All validation expression tests successful

clean:
	rm -f $(OBJS) $(TARGETS)
	rm -f valexp/*.gen

install: all
	install $(TARGETS) "$(PREFIX)/sbin/"

uninstall:
	for t in $(TARGETS); do rm -f "$(PREFIX)/sbin/$$t" ; done

