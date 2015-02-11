all: libstarttls.so libstarttls.a

clean:
	rm -f *.o libstarttls.so libstarttls.a

anew: clean all

.c.o:
	gcc -ggdb3 -pthread -fPIC -I ../include -I /usr/local/include -c -o $@ $<

libstarttls.so: libfun.o
	gcc -ggdb3 -pthread -shared -o $@ libfun.o

libstarttls.a: libfun.o
	rm -f $@
	ar rc $@ libfun.o

