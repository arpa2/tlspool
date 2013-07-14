all: libstarttls.so libstarttls.a testcli testsrv

.c.o:
	gcc -ggdb3 -pthread -fPIC -I ../include -I /usr/local/include -c -o $@ $<

libstarttls.so: libfun.o
	gcc -ggdb3 -pthread -shared -o $@ libfun.o

libstarttls.a: libfun.o
	rm -f $@
	ar rc $@ libfun.o

testcli: testcli.o libstarttls.a
	gcc -o $@ testcli.o libstarttls.a

testsrv: testsrv.o libstarttls.a
	gcc -o $@ testsrv.o libstarttls.a

