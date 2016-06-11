ifdef WINVER
TARGETS = libtlspool.dll libtlspool.lib
else
TARGETS = libtlspool.so libtlspool.a tlspool.pyc tlspool.pyo
endif

CFLAGS = -fPIC -I ../include

LDFLAGS =  

LIBS = 

PREFIX ?= /usr/local

ifdef WINVER
libtlspool_OBJS = libtlspool.o
else
libtlspool_OBJS = libtlspool.o libtlspool_lidentry.o libtlspool_pinentry.o
endif

OBJS = $(libtlspool_OBJS)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
libtlspool_OBJS += windows/syslog.o windows/socketpair.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
endif

all: $(TARGETS)

libtlspool.so: $(libtlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(libtlspool_OBJS) $(LIBS)

libtlspool.a: $(libtlspool_OBJS)
	rm -f "$@"
	ar rc "$@" $(libtlspool_OBJS)

tlspool.pyo: tlspool.py
	python -O -m compileall "$<"

tlspool.pyc: tlspool.py
	python -m compileall "$<"

libtlspool.dll: $(libtlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(libtlspool_OBJS) $(LIBS)

libtlspool.lib: windows/libtlspool.def
	$(DLLTOOL) --input-def "$<" --output-lib "$@"

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)

ifdef WINVER
install: all
	install libtlspool.dll "$(PREFIX)/lib/"
	install libtlspool.lib "$(PREFIX)/bin/"

uninstall:
	rm -f "$(PREFIX)/lib/libtlspool.dll"
else
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
endif
