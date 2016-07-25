# ifdef WINVER
# TARGETS = libtlspool.dll libtlspool.lib
# else
# TARGETS = libtlspool.so libtlspool.a tlspool.go
# endif

CFLAGS += -fPIC -I ../../include -std=gnu11

LDFLAGS += -std=gnu11

LDFLAGS += -ltlspool

LIBS += -lpthread

PREFIX ?= /usr/local

SWIG ?= swig

# ifdef WINVER
# CFLAGS += -D_WIN32_WINNT=0x0600 -I ../include/windows
# libtlspool_OBJS += windows/syslog.o windows/socketpair.o
# LIBS += -lkernel32 -ladvapi32 -lmsvcrt -lwsock32 -lws2_32
# endif

all: tlspool.c tlspool.go _tlspool.so

install: all
	# CFLAGS="$(CFLAGS)" \
	# LDFLAGS="$(LDFLAGS)" \
	go install

uninstall: all
	##### OOPS -- GO CANNOT HANDLE UNINSTALL #####
	# go uninstall

_tlspool.so: tlspool.c
	# CFLAGS="$(CFLAGS) $(GO_CFLAGS)" \
	# LDFLAGS="$(LDFLAGS) $(GO_LDFLAGS)" \
	# ln -sf ../../include/tlspool tlspool
	# go build -gccgoflags '$(CFLAGS)' -gcflags '$(CFLAGS)' -ldflags='$(LDFLAGS)'
	# go build -x -ldflags='$(LDFLAGS)'

defines.h:
	grep -h '^#define \(PIOF_\|PIOC_\|TLSPOOL_\)' ../../include/tlspool/commands.h ../../include/tlspool/starttls.h | grep -v 'PATH.*\\' | sed 's/\(\<0x80000000\>\)/-\1/g' | sort | uniq > "$@"

tlspool.c tlspool.go: go-tlspool.i ../swig-tlspool.i defines.h
	$(SWIG) -go -cgo -intgosize 64 -o "$@" "$<"
	sed -i 's/import "C"/\/\/ #cgo LDFLAGS: -ltlspool\n\0/' tlspool.go
	ln -sf ../../include/tlspool tlspool
	go build -work -x -ldflags='$(LDFLAGS)'

.c.o:
	$(CC) -c $(CFLAGS) -o "$@" "$<"

clean:
	rm -f $(OBJS) *.lo *.la *.so $(TARGETS)
	rm -rf defines.h
	rm -rf build

veryclean:
	rm -f tlspool.c tlspool.go

anew: clean all

