all: libstarttls.so

.c.o:
	gcc -ggdb3 -pthread -I ../include -I /usr/local/include -c -o $@ $<

libstarttls.so: libfun.o
	gcc -ggdb3 -pthread -shared -o $@ libfun.o

libstarttls.a: libfun.o
	rm -f $@
	ar -c $@ libfun.o

