ifdef WINVER
TARGETS = libtlspool.dll libtlspool.lib
else
TARGETS = libtlspool.so libtlspool.a tlspool.pyc tlspool.pyo
endif

WRAPPERS = python_tlspool.so

WRAPPERS_WISHLIST = ruby_tlspool.so perl_tlspool.so tcl_tlspool.so java_tlspool.so cis_tlspool.so php_tlspool.so lua_tlspool.so, go_tlspool.so, r_tlspool.so, modula3_tlspool.so

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

SWIG ?= swig

ifdef WINVER
CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
libtlspool_OBJS += windows/syslog.o windows/socketpair.o
LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
endif

PYTHON_CFLAGS = $(shell python-config --cflags)
PYTHON_LIBS = $(shell python-config --libs)

all: $(TARGETS) $(WRAPPERS)

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
	@echo '#'
	@echo '# Python libraries not yet installed'
	@echo '#'
	@echo '# You may need to run ldconfig to update the ld.so cache'
	@echo '#'
endif

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

.PHONEY: wrappers
wrappers: $(WRAPPERS)

python_tlspool.c: tlspool.i
	$(SWIG) -I../include -python -o "$@" "$<"

python_tlspool.so: python_tlspool.c libtlspool.so
	$(CC) -o "$@" -shared -fPIC -I../include $(PYTHON_CFLAGS) $(PYTHON_LIBS) "$<" -ltlspool

ruby_tlspool.so: tlspool.i
	$(SWIG) -I../include -ruby -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(RUBY_CFLAGS) $(RUBY_LIBS) "$(@:.so=.c)" -ltlspool

perl_tlspool.so: tlspool.i
	$(SWIG) -I../include -perl -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(PERL_CFLAGS) $(PERL_LIBS) "$(@:.so=.c)" -ltlspool

tcl_tlspool.so: tlspool.i
	$(SWIG) -I../include -tcl -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(TCL_CFLAGS) $(TCL_LIBS) "$(@:.so=.c)" -ltlspool

java_tlspool.so: tlspool.i
	$(SWIG) -I../include -java -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(JAVA_CFLAGS) $(JAVA_LIBS) "$(@:.so=.c)" -ltlspool

cis_tlspool.so: tlspool.i
	$(SWIG) -I../include -csharp -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(CIS_CFLAGS) $(CIS_LIBS) "$(@:.so=.c)" -ltlspool

php_tlspool.so: tlspool.i
	$(SWIG) -I../include -php -o "$(@:.so=.c)" "$<"
	$(CC) -o "$@" -shared -fPIC -I../include $(PHP_CFLAGS) $(PHP_LIBS) "$(@:.so=.c)" -ltlspool

