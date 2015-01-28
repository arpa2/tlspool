all: tlspool

debug: tlspool
	./tlspool -kc ../etc/tlspool.conf
	sleep 2
	gdb ./tlspool `pidof tlspool`

clean:
	rm -f *.o tlspool

anew: clean all

.PHONEY:

tags: .PHONEY
	ctags *.[ch] ../include/tlspool/*.h

.c.o:
	gcc -ggdb3 -pthread -I ../include -I /usr/local/include -I /usr/include/p11-kit-1 -c -o $@ $<

tlspool: daemon.o config.o manage.o service.o cache.o pinentry.o handler.o donai.o remote.o error.o
	@# gcc -ggdb3 -pthread -o $@ daemon.o config.o manage.o service.o cache.o pinentry.o handler.o donai.o remote.o error.o -L /usr/local/lib -L /usr/lib -L /usr/lib/x86_64-linux-gnu -lgnutls -ldb -lmemcached -lldap -lp11-kit -ltasn1
	gcc -ggdb3 -pthread -o $@ daemon.o config.o manage.o service.o cache.o pinentry.o handler.o donai.o remote.o error.o -L /usr/local/lib -L /usr/lib -L /usr/lib/x86_64-linux-gnu -ldb -lgnutls -lp11-kit -ltasn1
	@#STATLINK# gcc -ggdb3 -pthread -o $@ daemon.o config.o manage.o service.o cache.o pinentry.o handler.o donai.o remote.o error.o -L /usr/local/lib -L /usr/lib -L /usr/lib/x86_64-linux-gnu /usr/lib/libdb.a /usr/local/lib/libgnutls.a /usr/local/lib/libnettle.a /usr/local/lib/libhogweed.a /usr/lib/libgmp.a /usr/local/lib/libp11-kit.so /usr/lib/libz.a /usr/lib/libtasn1.a


#
# Compiling against GnuTLS .26 versions:
#  * may not work out well at all!  you are very much on your own!
#  * gcc -DGNUTLS_SEC_PARAM_LEGACY=2 -DGNUTLS_DEFAULT_HANDSHAKE_TIMEOUT=60 ...
#
