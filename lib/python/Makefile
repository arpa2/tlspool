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
	python setup.py install

uninstall: all
	python setup.py uninstall

_tlspool.so: tlspool.c
	#LATER# python setup.py build_ext --inplace
	$(CC) -shared -o "$@" $(CFLAGS) $(PYTHON_CFLAGS) $(LDFLAGS) $(PYTON_LDFLAGS) "$<" ../libtlspool.so

tlspool.c: py-tlspool.i ../swig-tlspool.i
	$(SWIG) -python -o "$@" "$<"

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) tlspool.py *.pyo *.pyc *.lo *.la *.so *.c $(TARGETS)
	rm -rf build

anew: clean all

