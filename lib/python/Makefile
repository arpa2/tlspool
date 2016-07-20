# ifdef WINVER
# TARGETS = libtlspool.dll libtlspool.lib
# else
# TARGETS = libtlspool.so libtlspool.a tlspool.pyc tlspool.pyo
# endif

CFLAGS += -fPIC -I ../../include -std=gnu11

LDFLAGS += -std=gnu11

LIBS += -lpthread

PREFIX ?= /usr/local

SWIG ?= swig

# ifdef WINVER
# CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
# libtlspool_OBJS += windows/syslog.o windows/socketpair.o
# LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
# endif

PYTHON_CFLAGS = $(shell python-config --cflags)
PYTHON_LIBS = $(shell python-config --libs)

all: _tlspool.so

install: all
	CFLAGS="$(CFLAGS) $(PYTHON_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(PYTHON_LDFLAGS)" \
	python setup.py install

uninstall: all
	python setup.py uninstall

_tlspool.so: tlspool.c
	@#MANUAL# $(CC) -shared -o "$@" $(CFLAGS) $(PYTHON_CFLAGS) $(LDFLAGS) $(PYTON_LDFLAGS) "$<" ../libtlspool.so
	CFLAGS="$(CFLAGS) $(PYTHON_CFLAGS)" \
	LDFLAGS="$(LDFLAGS) $(PYTHON_LDFLAGS)" \
	python setup.py build_ext --inplace

defines.h:
	grep -h '^#define \(PIOF_\|PIOC_\|TLSPOOL_\)' ../../include/tlspool/commands.h ../../include/tlspool/starttls.h | grep -v 'PATH.*\\' | sort | uniq > "$@"

tlspool.c: py-tlspool.i ../swig-tlspool.i defines.h
	$(SWIG) -python -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) tlspool.py *.pyo *.pyc *.lo *.la *.so *.c $(TARGETS)
	rm -rf defines.h
	rm -rf build

anew: clean all

