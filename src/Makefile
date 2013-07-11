all: tlspool

.c.o:
	gcc -ggdb3 -pthread -I ../include -I /usr/local/include -c -o $@ $<

tlspool: daemon.o config.o service.o cache.o pinentry.o handler.o
	gcc -ggdb3 -pthread -o $@ daemon.o config.o service.o cache.o pinentry.o handler.o /usr/local/lib/libgnutls.so.28 /usr/lib/libmemcached.so /usr/lib/libldap.so

