all: tlspool

clean:
	rm -f *.o tlspool

.c.o:
	gcc -ggdb3 -pthread -I ../include -I /usr/local/include -I /usr/include/p11-kit-1 -c -o $@ $<

tlspool: daemon.o config.o service.o cache.o pinentry.o handler.o remote.o
	gcc -ggdb3 -pthread -o $@ daemon.o config.o service.o cache.o pinentry.o handler.o remote.o -L /usr/local/lib -L /usr/lib -L /usr/lib/x86_64-linux-gnu -lgnutls -lmemcached -lldap -lp11-kit


#
# Compiling against GnuTLS .26 versions:
#  * may not work out well at all!  you are very much on your own!
#  * gcc -DGNUTLS_SEC_PARAM_LEGACY=2 -DGNUTLS_DEFAULT_HANDSHAKE_TIMEOUT=60 ...
#
