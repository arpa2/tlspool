ifdef WINVER
TARGETS = libtlspool.dll libtlspool.lib
else
TARGETS = libtlspool.so libtlspool.a
endif

#
# Wrappers for other languages.
# Built als language_tlspool.so to allow their co-existence in this directory.
# Installation may have to rename, e.g. pyhton_tlspool.so -> _tlspool.so
#
# Since the TLS Pool passes structures in and out, language wrappers may be needed.
#
WRAPPERS = python go
#WISHLIST: tcl ruby perl tcl java cis php lua go r modula3 javascript [and so on...]

CFLAGS += -fPIC -I ../include -std=gnu11
CFLAGS += -O0 -ggdb3

LDFLAGS += -std=gnu11

LIBS += -lpthread

PREFIX ?= /usr/local

ifdef WINVER
# TODO libtlspool_lidentry and libtlspool_pinentry
libtlspool_OBJS = libtlspool.o
else
libtlspool_OBJS = libtlspool.o libtlspool_lidentry.o libtlspool_pinentry.o libtlspool_configvar.o
endif

OBJS = $(libtlspool_OBJS)

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
libtlspool_OBJS += windows/syslog.o windows/socketpair.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
endif

PYTHON_CFLAGS = $(shell python-config --cflags)
PYTHON_LIBS = $(shell python-config --libs)

PERL_CFLAGS = -I/usr/lib/perl/5.14.2/CORE
PERL_LIBS = 

TCL_CFLAGS = -I/usr/include/tcl8.5
TCL_LIBS =

all: $(TARGETS) wrappers

wrappers:
	#DIY# @$(foreach w,$(WRAPPERS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(w)' all && ) echo Wrappers built for $(WRAPPERS)

libtlspool.so: $(libtlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(libtlspool_OBJS) $(LIBS)

libtlspool.a: $(libtlspool_OBJS)
	rm -f "$@"
	ar rc "$@" $(libtlspool_OBJS)

libtlspool.dll: $(libtlspool_OBJS)
	$(CC) -shared $(LDFLAGS) -o "$@" $(libtlspool_OBJS) $(LIBS)

libtlspool.lib: windows/libtlspool.def
	$(DLLTOOL) --input-def "$<" --output-lib "$@"

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) *.lo *.la $(TARGETS)
	#DIY# @$(foreach w,$(WRAPPERS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(w)' clean && ) echo Wrappers cleaned for $(WRAPPERS)

anew: clean all

install: all
ifdef WINVER
	install libtlspool.dll libtlspool.lib "$(DESTDIR)$(PREFIX)/bin/"
	mkdir -p "$(DESTDIR)$(PREFIX)/include/tlspool"
	install ../include/tlspool/starttls.h "$(DESTDIR)$(PREFIX)/include/tlspool"
	install ../include/tlspool/commands.h "$(DESTDIR)$(PREFIX)/include/tlspool"	
else	
	install libtlspool.so libtlspool.a "$(DESTDIR)$(PREFIX)/lib/"
	@echo '#'
	@echo '# Python libraries not yet installed'
	@echo '#'
	@echo '# You may need to run ldconfig to update the ld.so cache'
	@echo '#'
endif
	#DIY# @$(foreach w,$(WRAPPERS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(w)' install && ) echo Wrappers installed for $(WRAPPERS)

uninstall:
ifdef WINVER
	rm -f "$(DESTDIR)$(PREFIX)/bin/libtlspool.dll"
	rm -f "$(DESTDIR)$(PREFIX)/bin/libtlspool.lib"
	rm -rf "$(DESTDIR)$(PREFIX)/include/tlspool/"
else
	rm -f "$(DESTDIR)$(PREFIX)/lib/libtlspool.so"
	rm -f "$(DESTDIR)$(PREFIX)/lib/libtlspool.a"
	@echo '#'
	@echo '# Python libraries not yet removed'
	@echo '#'
endif
	#DIY# @$(foreach w,$(WRAPPERS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(w)' uninstall && ) echo Wrappers uninstalled for $(WRAPPERS)

