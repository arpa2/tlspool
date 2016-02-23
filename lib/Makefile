TARGETS = libtlspool.so libtlspool.a tlspool.pyc tlspool.pyo

CFLAGS = -fPIC -I ../include

LDFLAGS =  

LIBS = 

PREFIX = /usr/local

libtlspool_OBJS = libtlspool.o libtlspool_lidentry.o libtlspool_pinentry.o

OBJS = $(libtlspool_OBJS)

all: $(TARGETS)

libtlspool.so: $(libtlspool_OBJS)
	gcc -shared $(LDFLAGS) -o "$@" $(libtlspool_OBJS) $(LIBS)

libtlspool.a: $(libtlspool_OBJS)
	rm -f "$@"
	ar rc "$@" $(libtlspool_OBJS)

tlspool.pyo: tlspool.py
	python -O -m compileall "$<"

tlspool.pyc: tlspool.py
	python -m compileall "$<"

.c.o:
	gcc -c $(CFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)

install: all
	install libtlspool.so libtlspool.a "$(PREFIX)/lib/"
	@echo #
	@echo # Python libraries not yet installed
	@echo #
	@echo # You may need to run ldconfig to update the ld.so cache
	@echo #

uninstall:
	rm -f "$(PREFIX)/lib/libtlspool.so"
	rm -f "$(PREFIX)/lib/libtlspool.a"
	@echo #
	@echo # Python libraries not yet removed
	@echo #
