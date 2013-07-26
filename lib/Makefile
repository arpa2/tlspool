all: libstarttls.so libstarttls.a tlstunnel testcli testsrv

clean:
	rm -f *.o libstarttls.so libstarttls.a testcli testsrv tlstunnel

.c.o:
	gcc -ggdb3 -pthread -fPIC -I ../include -I /usr/local/include -c -o $@ $<

libstarttls.so: libfun.o
	gcc -ggdb3 -pthread -shared -o $@ libfun.o

libstarttls.a: libfun.o
	rm -f $@
	ar rc $@ libfun.o

tlstunnel: tlstunnel.o libstarttls.so
	gcc -pthread -I ../include -o $@ tlstunnel.o libstarttls.so

testcli: testcli.o libstarttls.a
	gcc -o $@ testcli.o libstarttls.a

testsrv: testsrv.o libstarttls.a
	gcc -o $@ testsrv.o libstarttls.a

