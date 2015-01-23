all: tlspool-test-ca-cert.der tlspool-test-client-cert.der tlspool-test-server-cert.der localid.db disclose.db

tlspool-test-ca-cert.der: tlspool-test-ca-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

tlspool-test-client-cert.der: tlspool-test-client-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

tlspool-test-server-cert.der: tlspool-test-server-cert.pem
	openssl x509 -inform pem -outform der -in $< -out $@

tlspool-test-server-certchain.der: tlspool-test-server-cert.der tlspool-test-ca-cert.der
	cat > $@ tlspool-test-server-cert.der tlspool-test-ca-cert.der

localid.db: tlspool-test-client-cert.der tlspool-test-server-cert.der tlspool-test-client-key.pem tlspool-test-server-key.pem tlspool-test-client-pubkey-pkcs11.pgp tlspool-test-client-pubkey.asc tlspool-test-server-pubkey-pkcs11.pgp tlspool-test-server-pubkey.asc
	# rm -f $@
	../tool/set_localid $@ testcli@tlspool.arpa2.lab OpenPGP,client 'pkcs11:model=SoftHSM;manufacturer=SoftHSM;serial=1;token=TLS%20Pool%20testdata;id=obj1id;object=obj1label;object-type=private' tlspool-test-client-pubkey-pkcs11.pgp
	../tool/set_localid $@ testsrv@tlspool.arpa2.lab OpenPGP,server 'pkcs11:model=SoftHSM;manufacturer=SoftHSM;serial=1;token=TLS%20Pool%20testdata;id=obj2id;object=obj2label;object-type=private' tlspool-test-server-pubkey-pkcs11.pgp
	../tool/set_localid $@ testcli@tlspool.arpa2.lab x.509,client 'pkcs11:model=SoftHSM;manufacturer=SoftHSM;serial=1;token=TLS%20Pool%20testdata;id=obj3id;object=obj3label;object-type=private' tlspool-test-client-cert.der
	../tool/set_localid $@ testsrv@tlspool.arpa2.lab x.509,server 'pkcs11:model=SoftHSM;manufacturer=SoftHSM;serial=1;token=TLS%20Pool%20testdata;id=obj4id;object=obj4label;object-type=private' tlspool-test-server-cert.der

localid-chained.db: localid.db tlspool-test-server-certchain.der
	cp localid.db $@
	../tool/set_localid $@ testsrv@tlspool.arpa2.lab x.509,server,chained 'pkcs11:model=SoftHSM;manufacturer=SoftHSM;serial=1;token=TLS%20Pool%20testdata;id=obj4id;object=obj4label;object-type=private' tlspool-test-server-certchain.der
	@echo '******************************************************************************'
	@echo 'You can move localid-chained.db in the position of localid.db to test chaining'
	@echo '******************************************************************************'

#
# Did this:
#
# openssl pkcs8 -topk8 -in tlspool-test-client-key.pem -out tlspool-test-client-key-pkcs8.pem -inform pem -outform pem -nocrypt
# openssl pkcs8 -topk8 -in tlspool-test-server-key.pem -out tlspool-test-server-key-pkcs8.pem -inform pem -outform pem -nocrypt
#
# softhsm-util --import tlspool-test-client-key-pkcs8.pem --slot 0 --label 'TLS Pool testdata' --id '6f626a336964'
# softhsm-util --import tlspool-test-server-key-pkcs8.pem --slot 0 --label 'TLS Pool testdata' --id '6f626a346964'

disclose.db:
	# rm -f $@
	../tool/set_disclose $@ @.arpa2.lab testcli@tlspool.arpa2.lab testsrv@tlspool.arpa2.lab

clean:
	rm -f *.der localid.db disclose.db

anew: clean all

