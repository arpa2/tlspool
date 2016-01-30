#
# testdata/Makefile -- for TLS Pool developers
#
# This file creates elements in the testdata/ directory used for testing
# and is in fact a requisite for tool/testcli, tool/testsrv, tool/testpeer.
#
# Targets of interest:
#  * all -- makes sure you can go ahead
#  * rebuild-pkcs11 -- wipes your PKCS #11 token (really!) and starts it fresh
#  * rebuild-cert -- wipes your certificate files and rebuilds them
#  * rebuild-pgp -- wipes your OpenPGP public keys and rebuilds them
#  * rebuild-db -- wipes your public credentials databases and refills them
# The last four should be run in order; later ones may depend on predecessors.
#
# From: Rick van Rein <rick@openfortress.nl>
#


#
# The following numbered keys are created here:
#
# 1. test client OpenPGP key: testcli@tlspool.arpa2.lab
# 2. test server OpenPGP key: testsrv@tlspool.arpa2.lab
# 3. test client certificate: testcli@tlspool.arpa2.lab
# 4. test server certificate: testsrv@tlspool.arpa2.lab
# 5. test CA certificate: testca@tlspool.arpa2.lab
# 6. test on-the-fly signing CA certificate: flying-signer@tlspool.arpa2.lab
#

TARGET_PKCS11=$(PRIVKEYGEN)
TARGET_CERT=tlspool-test-client-cert.der tlspool-test-server-cert.der tlspool-test-ca-cert.der tlspool-test-flying-signer.der
TARGET_PGP11=tlspool-test-client-pubkey.pgp tlspool-test-server-pubkey.pgp
TARGET_DB=localid.db disclose.db


#
# Setting for the configuration file tlspool.conf
#
CONFFILE=$(shell pwd)/../etc/tlspool.conf

#
# Load a few things from tlspool.conf; these are assumed present while testing
#
P11PIN=$(shell sed < $(CONFFILE) -n 's/^pkcs11_pin //p')
P11LIB=$(shell sed < $(CONFFILE) -n 's/^pkcs11_path //p')
P11URI=$(shell sed < $(CONFFILE) -n 's/^pkcs11_token pkcs11:/pkcs11:/p')

#
# Embellish p11tool command; if fixed, provide the PKCS #11 PIN automatically
#
ifeq ($(P11PIN),)
P11TOOL=p11tool --provider $(P11LIB) --login
CERTTOOL=certtool --provider $(P11LIB) --outder
else
P11TOOL=GNUTLS_PIN=$(P11PIN) p11tool --provider $(P11LIB) --login
CERTTOOL=GNUTLS_PIN=$(P11PIN) certtool --provider $(P11LIB) --outder
endif

#
# Establish which private keys need to be generated on the PKCS #11 token
#

PRIVKEY1=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj1label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY1),)
PRIVKEYGEN += privkey1
endif

PRIVKEY2=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj2label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY2),)
PRIVKEYGEN += privkey2
endif

PRIVKEY3=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj3label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY3),)
PRIVKEYGEN += privkey3
endif

PRIVKEY4=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj4label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY4),)
PRIVKEYGEN += privkey4
endif

PRIVKEY5=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj5label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY5),)
PRIVKEYGEN += privkey5
endif

PRIVKEY6=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj6label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY6),)
PRIVKEYGEN += privkey6
endif


#
# General rules for cleaning and filling (together, rebuilding) parts
#

.PHONY: all rebuild-pkcs11 rebuild-certs rebuild-pgp rebuild-db
.PHONY:       clean-pkcs11   clean-certs   clean-pgp   clean-db
.PHONY:      refill-pkcs11  refill-certs  refill-pgp  refill-db

all: fill-pkcs11 fill-certs fill-pgp fill-db

rebuild-pkcs11: clean-pkcs11 fill-pkcs11

rebuild-certs: clean-certs fill-certs

rebuild-pgp: clean-pgp fill-pgp

rebuild-db: clean-db fill-db

clean-pkcs11:
	#
	# WARNING -- PROCEED WITH CARE
	#
	# About to wipe your PKCS #11 object store.
	# If this is unintended, stop now.
	#
	$(P11TOOL) --initialize '$(P11URI)'

fill-pkcs11: $(PRIVKEYGEN)

clean-certs:
	rm -f $(TARGET_CERT)

fill-certs: $(TARGET_CERT)

clean-pgp:
	rm -f $(TARGET_PGP11)

fill-pgp: $(TARGET_PGP11)

clean-db:
	rm -f $(TARGET_DB)

fill-db: $(TARGET_DB)


#
# Rule for private key generation on the PKCS #11 token
#
# Old: Generate test keys externally and import using SoftHSM-specific tool:
#
# openssl pkcs8 -topk8 -in tlspool-test-client-key.pem -out tlspool-test-client-key-pkcs8.pem -inform pem -outform pem -nocrypt
# openssl pkcs8 -topk8 -in tlspool-test-server-key.pem -out tlspool-test-server-key-pkcs8.pem -inform pem -outform pem -nocrypt
#
# softhsm-util --import tlspool-test-client-key-pkcs8.pem --slot 0 --label 'TLS Pool testdata' --id '6f626a336964'
# softhsm-util --import tlspool-test-server-key-pkcs8.pem --slot 0 --label 'TLS Pool testdata' --id '6f626a346964'
#
# Could alternatively do:
#
# $(P11TOOL) --initialize '$(P11URI)'
# $(P11TOOL) --generate-rsa --bits 2048 --label objXlabel --id objXid --outfile xxx.pem '$(P11URI)'
# ...

.PHONY: privkey1 privkey2 privkey3 privkey4 privkey5

privkey1:
	@echo 'Generating private key #1 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj1label '$(P11URI)'

privkey2:
	@echo 'Generating private key #2 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj2label '$(P11URI)'

privkey3:
	@echo 'Generating private key #3 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj3label '$(P11URI)'

privkey4:
	@echo 'Generating private key #4 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj4label '$(P11URI)'

privkey5:
	@echo 'Generating private key #5 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj5label '$(P11URI)'

privkey6:
	@echo 'Generating private key #6 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits 2048 --label=obj6label '$(P11URI)'


#
# Produce binary DER certificates (without going through the textual "PEM" form)
#

# Key 1: OpenPGP Client Certificate
tlspool-test-client-pubkey.pgp:
	echo Using PRIVKEY1, '$(PRIVKEY1)'
	#TODO# tlspool-test-client-pubkey.pgp from PRIVKEY1
	#TODO# $(CERTTOOL) --pgp-certificate-info --infile $@ --inraw > $(@:.pgp=.txt)

# Key 2: OpenPGP Server Certificate
tlspool-test-server-pubkey.pgp:
	echo Using PRIVKEY2, '$(PRIVKEY2)'
	#TODO# tlspool-test-client-pubkey.pgp from PRIVKEY2
	#TODO# $(CERTTOOL) --pgp-certificate-info --infile $@ --inraw > $(@:.pgp=.txt)

# Key 3: X.509 Client Certificate
tlspool-test-client-cert.der: tlspool-test-client-cert.template
	echo Using PRIVKEY3, '$(PRIVKEY3)'
	$(CERTTOOL) --outfile $@ --generate-self-signed --load-privkey='$(PRIVKEY3)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder > $(@:.der=.txt)

# Key 4: X.509 Server Certificate
tlspool-test-server-cert.der: tlspool-test-server-cert.template
	echo Using PRIVKEY4, '$(PRIVKEY4)'
	$(CERTTOOL) --outfile $@ --generate-self-signed --load-privkey='$(PRIVKEY4)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder > $(@:.der=.txt)

# Key 5: Test CA (for chained certificates)
tlspool-test-ca-cert.der: tlspool-test-ca-cert.template
	echo Using PRIVKEY5, '$(PRIVKEY5)'
	$(CERTTOOL) --outfile $@ --generate-self-signed --load-privkey='$(PRIVKEY5)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder > $(@:.der=.txt)

#TODO# # Based on key 5: certificate chain
#TODO# tlspool-test-server-certchain.der: tlspool-test-server-cert.der tlspool-test-ca-cert.der
#TODO# 	cat > $@ tlspool-test-server-cert.der tlspool-test-ca-cert.der

# Key 5: Flying Signer CA (loaded into TLS Pool and automated)

tlspool-test-flying-signer.der: tlspool-test-flying-signer.template
	echo Using PRIVKEY6, '$(PRIVKEY6)'
	$(CERTTOOL) --outfile $@ --generate-self-signed --load-privkey='$(PRIVKEY6)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder > $(@:.der=.txt)

#
# Create localid.db from scratch
#

localid.db:
	../tool/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab OpenPGP,client '$(PRIVKEY1)' tlspool-test-client-pubkey.pgp
	../tool/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab OpenPGP,server '$(P11URI);id=obj2id;object=obj2label;object-type=private' tlspool-test-server-pubkey.pgp
	../tool/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab x.509,client '$(P11URI);id=obj3id;object=obj3label;object-type=private' tlspool-test-client-cert.der
	../tool/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab x.509,server '$(P11URI);id=obj4id;object=obj4label;object-type=private' tlspool-test-server-cert.der

disclose.db:
	../tool/set_disclose $(CONFFILE) @.arpa2.lab testcli@tlspool.arpa2.lab testsrv@tlspool.arpa2.lab
	../tool/set_disclose $(CONFFILE) .arpa2.lab tlspool.arpa2.lab

clean:
	rm -f *.der localid.db disclose.db
	#TODO# rm -f *.pem
	#TODO# rm -f tlspool.env/*

anew: clean all

