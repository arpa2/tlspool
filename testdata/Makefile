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
# 7. test server certificate: tlspool.arpa2.lab
#


#
# Setting for the configuration file tlspool.conf
# Setting of the number of RSA private key bits (radically ignoring 2^n trends)
#
CONFFILE ?= $(shell pwd)/../etc/tlspool.conf
RSABITS ?= 2000
PGPRSABITS ?= 2048

#
# The directory with tools, defaulting to ../tool in the git base
# Note that testdata is meant for developers, so assuming git is usually the best
#
TOOLDIR ?= $(shell pwd)/../tool

#
# Load a few things from tlspool.conf; these are assumed present while testing
#
P11PIN=$(shell sed < $(CONFFILE) -n 's/^pkcs11_pin //p')
P11LIB=$(shell sed < $(CONFFILE) -n 's/^pkcs11_path //p')
P11URI=$(shell sed < $(CONFFILE) -n 's/^pkcs11_token pkcs11:/pkcs11:/p')
DMNUSR=$(shell sed < $(CONFFILE) -n 's/^daemon_user //p')
DMNGRP=$(shell sed < $(CONFFILE) -n 's/^daemon_group //p')
BDBENV=$(shell sed < $(CONFFILE) -n 's/^dbenv_dir //p')

#
# Embellish p11tool command; if fixed, provide the PKCS #11 PIN automatically
#
ifeq ($(P11PIN),)
P11TOOL=p11tool --provider $(P11LIB) --login
CERTTOOL=certtool --provider $(P11LIB)
PGPTOOL=$(TOOLDIR)/pgp11_genkey
else
P11TOOL=GNUTLS_PIN=$(P11PIN) p11tool --provider $(P11LIB) --login
CERTTOOL=GNUTLS_PIN=$(P11PIN) certtool --provider $(P11LIB)
PGPTOOL=GNUTLS_PIN=$(P11PIN) $(TOOLDIR)/pgp11_genkey
endif

#
# Establish which private keys need to be generated on the PKCS #11 token
#

PRIVKEY1=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj1label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY1),)
PRIVKEYGEN += privkey1
PRIVKEY1=$(P11URI);id=%30%31;label=obj1label;type=private
endif

PRIVKEY2=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj2label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY2),)
PRIVKEYGEN += privkey2
PRIVKEY2=$(P11URI);id=%30%32;label=obj2label;type=private
endif

PRIVKEY3=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj3label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY3),)
PRIVKEYGEN += privkey3
PRIVKEY3=$(P11URI);id=%30%33;label=obj3label;type=private
endif

PRIVKEY4=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj4label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY4),)
PRIVKEYGEN += privkey4
PRIVKEY4=$(P11URI);id=%30%34;label=obj4label;type=private
endif

PRIVKEY5=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj5label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY5),)
PRIVKEYGEN += privkey5
PRIVKEY5=$(P11URI);id=%30%35;label=obj5label;type=private
endif

PRIVKEY6=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj6label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY6),)
PRIVKEYGEN += privkey6
PRIVKEY6=$(P11URI);id=%30%36;label=obj6label;type=private
endif

PRIVKEY7=$(shell $(P11TOOL) --list-privkeys '$(P11URI)' | sed -e '/object=obj7label/!d' -e 's/^[ \t]*URL: //')
ifeq ($(PRIVKEY7),)
PRIVKEYGEN += privkey7
PRIVKEY7=$(P11URI);id=%30%37;label=obj7label;type=private
endif


#
# General rules for cleaning and filling (together, rebuilding) parts
#

TARGET_PKCS11=$(PRIVKEYGEN)
TARGET_CERT=tlspool-test-client-cert.der tlspool-test-server-cert.der tlspool-test-ca-cert.der tlspool-test-flying-signer.der tlspool-test-webhost-cert.der tlspool-test-srp
TARGET_PGP=tlspool-test-client-pubkey.pgp tlspool-test-server-pubkey.pgp
TARGET_DB=localid.db disclose.db trust.db
TARGET_DBE=tlspool.env

.PHONY: all rebuild-pkcs11 rebuild-cert rebuild-pgp rebuild-db
.PHONY:       clean-pkcs11   clean-cert   clean-pgp   clean-db
.PHONY:      refill-pkcs11  refill-cert  refill-pgp  refill-db

all: fill-pkcs11 fill-cert fill-pgp fill-db

rebuild-pkcs11: clean-pkcs11 fill-pkcs11
	#
	# You should continue with "make rebuild-cert rebuild-pgp rebuild-db"
	#

rebuild-cert: clean-cert fill-cert
	#
	# You should continue with "make rebuild-db"
	#

rebuild-pgp: clean-pgp fill-pgp
	#
	# You should continue with "make rebuild-db"
	#

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

clean-cert:
	rm -f $(TARGET_CERT)

fill-cert: $(TARGET_CERT)

clean-pgp:
	rm -f $(TARGET_PGP)

fill-pgp: $(TARGET_PGP)

clean-db:
	if pidof tlspool ; then echo First stop TLS Pool ; exit 1 ; fi
	rm -f $(TARGET_DB)
	mkdir -p $(TARGET_DBE)
	rm -f $(TARGET_DBE)/*
	rmdir $(TARGET_DBE)

fill-db: $(TARGET_DBE) $(TARGET_DB)


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
# $(P11TOOL) --generate-rsa --bits $(RSABITS) --label objXlabel --id objXid --outfile xxx.pem '$(P11URI)'
# ...

.PHONY: privkey1 privkey2 privkey3 privkey4 privkey5 privkey6 privkey7

privkey1:
	@echo 'Generating private key #1 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(PGPRSABITS) --label=obj1label --id=3031 --outfile=/dev/null '$(P11URI)'

privkey2:
	@echo 'Generating private key #2 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(PGPRSABITS) --label=obj2label --id=3032 --outfile=/dev/null '$(P11URI)'

privkey3:
	@echo 'Generating private key #3 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(RSABITS) --label=obj3label --id=3033 --outfile=/dev/null '$(P11URI)'

privkey4:
	@echo 'Generating private key #4 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(RSABITS) --label=obj4label --id=3034 --outfile=/dev/null '$(P11URI)'

privkey5:
	@echo 'Generating private key #5 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(RSABITS) --label=obj5label --id=3035 --outfile=/dev/null '$(P11URI)'

privkey6:
	@echo 'Generating private key #6 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(RSABITS) --label=obj6label --id=3036 --outfile=/dev/null '$(P11URI)'

privkey7:
	@echo 'Generating private key #7 on PKCS #11 token'
	$(P11TOOL) --generate-rsa --bits $(RSABITS) --label=obj7label --id=3037 --outfile=/dev/null '$(P11URI)'


#
# Produce binary DER certificates (without going through the textual "PEM" form)
#

# Key 1: OpenPGP Client Certificate
tlspool-test-client-pubkey.pgp:
	echo Using PRIVKEY1, '$(PRIVKEY1)'
	$(PGPTOOL) $(P11LIB) '$(PRIVKEY1)' 'OpenPGP Test Client <testcli@tlspool.arpa2.lab>' $@
	$(CERTTOOL) --pgp-certificate-info --infile $@ --inraw --outfile $(@:.pgp=.asc)

# Key 2: OpenPGP Server Certificate
tlspool-test-server-pubkey.pgp:
	echo Using PRIVKEY2, '$(PRIVKEY2)'
	$(PGPTOOL) $(P11LIB) '$(PRIVKEY2)' 'OpenPGP Test Server <testsrv@tlspool.arpa2.lab>' $@
	$(CERTTOOL) --pgp-certificate-info --infile $@ --inraw --outfile $(@:.pgp=.asc)

# Key 3: X.509 Client Certificate
tlspool-test-client-cert.der: tlspool-test-client-cert.template
	echo Using PRIVKEY3, '$(PRIVKEY3)'
	$(CERTTOOL) --outfile $@ --outder --generate-self-signed --load-privkey='$(PRIVKEY3)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder --outfile $(@:.der=.pem)

# Key 4: X.509 Server Certificate with user@ domain name
tlspool-test-server-cert.der: tlspool-test-server-cert.template
	echo Using PRIVKEY4, '$(PRIVKEY4)'
	$(CERTTOOL) --outfile $@ --outder --generate-self-signed --load-privkey='$(PRIVKEY4)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder --outfile $(@:.der=.pem)

# Key 5: Test CA (for chained certificates)
tlspool-test-ca-cert.der: tlspool-test-ca-cert.template
	echo Using PRIVKEY5, '$(PRIVKEY5)'
	$(CERTTOOL) --outfile $@ --outder --generate-self-signed --load-privkey='$(PRIVKEY5)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder --outfile $(@:.der=.pem)

#TODO# # Based on key 5: certificate chain
#TODO# tlspool-test-server-certchain.der: tlspool-test-server-cert.der tlspool-test-ca-cert.der
#TODO# 	cat > $@ tlspool-test-server-cert.der tlspool-test-ca-cert.der

# Key 6: Flying Signer CA (loaded into TLS Pool and automated)

tlspool-test-flying-signer.der: tlspool-test-flying-signer.template
	echo Using PRIVKEY6, '$(PRIVKEY6)'
	$(CERTTOOL) --outfile $@ --outder --generate-self-signed --load-privkey='$(PRIVKEY6)' --template=$<
	$(CERTTOOL) --certificate-info --infile $@ --inder --outfile $(@:.der=.pem)

# Key 7: X.509 Server Certificate with just a host name
tlspool-test-webhost-cert.der: tlspool-test-webhost-cert.template
	echo Using PRIVKEY7, '$(PRIVKEY7)'
	$(CERTTOOL) --outfile $@ --outder --generate-self-signed --load-privkey='$(PRIVKEY7)' --template=$<


# Turn a .der into a .keyid
%.keyid: %.der
	$(CERTTOOL) --inraw --infile $< -i | sed -e '1,/Public Key ID:/d' -e '/Public key.s random art:/,$$d' -e 's/[ \t]*//' > $@

#
# SRP credentials are loaded from fixed paths ../testdata/tlspool-test-srp.* for now
# Yes, this is ugly, we're still hoping to use SRP #11 instead, as defined on
# https://github.com/arpa2/srp-pkcs11
#

tlspool-test-srp:
	chown $(DMNUSR):$(DMNGRP) $@.conf $@.passwd


#
# Create localid.db from scratch
#

tlspool.env:
	mkdir -p $@
	chown $(DMNUSR):$(DMNGRP) $@

localid.db: tlspool.env
	$(TOOLDIR)/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab OpenPGP,client '$(PRIVKEY1)' tlspool-test-client-pubkey.pgp
	$(TOOLDIR)/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab OpenPGP,server '$(PRIVKEY2)' tlspool-test-server-pubkey.pgp
	$(TOOLDIR)/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab x.509,client '$(PRIVKEY3)' tlspool-test-client-cert.der
	$(TOOLDIR)/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab x.509,server '$(PRIVKEY4)' tlspool-test-server-cert.der
	$(TOOLDIR)/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab kerberos,client,server 'pkcs11:some;place' /dev/null
	$(TOOLDIR)/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab kerberos,client,server 'pkcs11:some;place' /dev/null
	#REALISTIC-BUT-NOT-YET# $(TOOLDIR)/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab valexp,client,server 'tI&' /dev/null
	#REALISTIC-BUT-NOT-YET# $(TOOLDIR)/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab valexp,client,server 'It&' /dev/null
	$(TOOLDIR)/set_localid $(CONFFILE) testcli@tlspool.arpa2.lab valexp,client,server '1' /dev/null
	$(TOOLDIR)/set_localid $(CONFFILE) testsrv@tlspool.arpa2.lab valexp,client,server '1' /dev/null
	$(TOOLDIR)/set_localid $(CONFFILE) tlspool.arpa2.lab x.509,server,client '$(PRIVKEY7)' tlspool-test-webhost-cert.der
	chown $(DMNUSR):$(DMNGRP) $(BDBENV)/* $@

disclose.db: tlspool.env localid.db
	$(TOOLDIR)/set_disclose $(CONFFILE) @.arpa2.lab testcli@tlspool.arpa2.lab testsrv@tlspool.arpa2.lab
	$(TOOLDIR)/set_disclose $(CONFFILE) . tlspool.arpa2.lab
	chown $(DMNUSR):$(DMNGRP) $(BDBENV)/* $@

trust.db: tlspool.env tlspool-test-ca-cert.der tlspool-test-ca-cert.keyid tlspool-test-flying-signer.der tlspool-test-flying-signer.keyid
	$(TOOLDIR)/set_trust $(CONFFILE) x509,client,server `cat tlspool-test-ca-cert.keyid` 1 tlspool-test-ca-cert.der
	$(TOOLDIR)/set_trust $(CONFFILE) x509,client,server `cat tlspool-test-flying-signer.keyid` 1 tlspool-test-flying-signer.der
	chown $(DMNUSR):$(DMNGRP) $(BDBENV)/* $@

clean: clean-db
	rm -f *.der *.pgp
	rm -f *.pem *.asc

anchors: trust.db
	@$(foreach rootca,$(shell ls -1 $(shell pwd)/trust-anchors/*.pem),$(CERTTOOL) --certificate-info --infile "$(rootca)" --outder --outfile "$(rootca:.pem=.der)" && ) echo 'Converted all root CA .pem to .der'
	@$(foreach rootca,$(shell ls -1 $(shell pwd)/trust-anchors/*.der),$(CERTTOOL) --inraw --infile "$(rootca)" -i | sed -e '1,/Public Key ID:/d' -e '/Public key.s random art:/,$$d' -e 's/[ \t]*//' > "$(rootca:.der=.keyid)" && ) echo 'Converted all root CA .der to .keyid'
	@$(foreach rootca,$(shell ls -1 $(shell pwd)/trust-anchors/*.der),$(TOOLDIR)/set_trust $(CONFFILE) x509,client,server `cat "$(rootca:.der=.keyid)"` 1 "$(rootca)" && ) echo 'Imported  all root CA .der into trust.db'

anew: clean all

