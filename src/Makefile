all: tlspool

.c.o:
	gcc -I ../include -I /usr/local/include -c -o $@ $<

tlspool: daemon.o config.o service.o cache.o
	gcc -o $@ daemon.o config.o service.o cache.o /usr/local/lib/libgnutls.so.28 /usr/lib/libmemcached.so /usr/lib/libldap.so

