ifdef WINVER
TARGETS = libtlspool.dll libtlspool.lib
else
TARGETS = libtlspool.so libtlspool.a tlspool.pyc tlspool.pyo
endif

CFLAGS += -fPIC -I ../include -std=gnu11

LDFLAGS += -std=gnu11

LIBS += -lpthread

PREFIX ?= /usr/local

ifdef WINVER
# TODO libtlspool_lidentry and libtlspool_pinentry
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
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)

anew: clean all

install: all
ifdef WINVER
	install libtlspool.dll libtlspool.lib "$(DESTDIR)$(PREFIX)/bin/"
	mkdir -p "$(DESTDIR)$(PREFIX)/include/tlspool"
	install ../include/tlspool/starttls.h "$(DESTDIR)$(PREFIX)/include/tlspool"
	install ../include/tlspool/commands.h "$(DESTDIR)$(PREFIX)/include/tlspool"	
else	
	install libtlspool.so libtlspool.a "$(DESTDIR)$(PREFIX)/lib/"
	@echo #
	@echo # Python libraries not yet installed
	@echo #
	@echo # You may need to run ldconfig to update the ld.so cache
	@echo #
endif

uninstall:
ifdef WINVER
	rm -f "$(DESTDIR)$(PREFIX)/bin/libtlspool.dll"
	rm -f "$(DESTDIR)$(PREFIX)/bin/libtlspool.lib"
	rm -rf "$(DESTDIR)$(PREFIX)/include/tlspool/"
else
	rm -f "$(DESTDIR)$(PREFIX)/lib/libtlspool.so"
	rm -f "$(DESTDIR)$(PREFIX)/lib/libtlspool.a"
	@echo #
	@echo # Python libraries not yet removed
	@echo #
endif
