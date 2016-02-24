
PREFIX = /usr/local

DOCS = socketprotocol.rst databases.rst identities.rst pkcs11.rst validation.md \
	startxxx.md p2p-tls.md tool/ircproxy-explained.md \
	localid-selection.md anonymising-precursor.md

LICS = COPYRIGHT.MD LICENSE-DAEMON.MD LICENSE-DOCS.MD LICENSE-USERSPACE.MD \
	README INSTALL TODO

MAN3 = tlspool_socket tlspool_starttls \
	tlspool_ping tlspool_prng \
	tlspool_pin_service tlspool_localid_service \
	tlspool_control_detach tlspool_control_reattach

MAN8 = tlspool tlstunnel


all:
	@echo -n

install: all
	mkdir -p "$(PREFIX)/share/doc/tlspool/"
	mkdir -p "$(PREFIX)/share/man/man3/"
	mkdir -p "$(PREFIX)/share/man/man8/"
	@$(foreach l,$(LICS),install '../$l' '$(PREFIX)/share/doc/tlspool/' && ) echo Installed license documents
	@$(foreach d,$(DOCS),install '$d' '$(PFEFIX)/share/doc/tlspool/' && ) echo Installed technical documentation
	@$(foreach d,$(MAN8),install 'man/$m.man' '$(PREFIX)/share/man/man8/$m.8' && ) echo Installed man page section 8
	@$(foreach d,$(MAN3),install 'man/$m.man' '$(PREFIX)/share/man/man3/$m.3' && ) echo Installed man page section 3
	@echo #
	@echo # You may need to run makewhatis or similar to update manual page caches
	@echo #

uninstall:
	@($foreach $m,$(MAN3),rm -f '$(PREFIX)/share/man/man3/$m.3' && ) echo Uninstalled man page section 3
	@($foreach $m,$(MAN8),rm -f '$(PREFIX)/share/man/man8/$m.8' && ) echo Uninstalled man page section 8
	@($foreach $d,$(DOCS),rm -f "$(PREFIX)/share/doc/tlspool/`basename '$d'` && ) echo Uninstalled technical documentation
	@($foreach $l,$(LICS),rm -f '$(PREFIX)/share/doc/tlspool/$l' && ) echo Uninstalled license documents
	rmdir --ignore-fail-on-non-empty "$(PREFIX)/share/doc/tlspool/"

clean:
	@echo -n

