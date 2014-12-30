all: tlspool-test-ca-cert.der tlspool-test-client-cert.der tlspool-test-server-cert.der localid.db disclose.db

tlspool-test-ca-cert.der: tlspool-test-ca-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

tlspool-test-client-cert.der: tlspool-test-client-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

tlspool-test-server-cert.der: tlspool-test-server-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

localid.db: tlspool-test-client-cert.der tlspool-test-server-cert.der tlspool-test-client-key.pem tlspool-test-server-key.pem tlspool-test-client-pubkey.bin tlspool-test-client-pubkey.asc tlspool-test-server-pubkey.bin tlspool-test-server-pubkey.asc
	# rm -f $@
	../tool/set_localid $@ testcli@tlspool.arpa2.lab x.509,client ../testdata/tlspool-test-client-key.pem tlspool-test-client-cert.der
	../tool/set_localid $@ testsrv@tlspool.arpa2.lab x.509,server ../testdata/tlspool-test-server-key.pem tlspool-test-server-cert.der
	../tool/set_localid $@ testcli@tlspool.arpa2.lab openpgp,client ../testdata/tlspool-test-client-privkey.asc tlspool-test-client-pubkey.bin
	../tool/set_localid $@ testsrv@tlspool.arpa2.lab openpgp,server ../testdata/tlspool-test-server-privkey.asc tlspool-test-server-pubkey.bin

disclose.db:
	# rm -f $@
	../tool/set_disclose $@ @.arpa2.lab testcli@tlspool.arpa2.lab testsrv@tlspool.arpa2.lab

clean:
	rm -f *.der localid.db disclose.db

anew: clean all

