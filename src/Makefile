all: tlspool

clean:
	rm -f *.o tlspool

.c.o:
	gcc -ggdb3 -pthread -I ../include -I /usr/local/include -c -o $@ $<

tlspool: daemon.o config.o service.o cache.o pinentry.o handler.o
	gcc -ggdb3 -pthread -o $@ daemon.o config.o service.o cache.o pinentry.o handler.o -L /usr/local/lib -L /usr/lib -lgnutls -lmemcached -lldap

