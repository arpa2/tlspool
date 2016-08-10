
PREFIX ?= /usr/local/

DOCS = socketprotocol.rst databases.rst identities.rst pkcs11.rst validation.md \
	startxxx.md p2p-tls.md tool/ircproxy-explained.md \
	localid-selection.md anonymising-precursor.md

LICS = COPYRIGHT.MD LICENSE-DAEMON.MD LICENSE-DOCS.MD LICENSE-USERSPACE.MD \
	README INSTALL TODO

MAN3 = tlspool_socket tlspool_starttls \
	tlspool_ping tlspool_prng \
	tlspool_pin_service tlspool_localid_service \
	tlspool_control_detach tlspool_control_reattach \
	tlspool_configvar

MAN8 = tlspool tlstunnel


all:
	@echo -n

install: all
	mkdir -p "$(DESTDIR)$(PREFIX)/share/doc/tlspool/"
	mkdir -p "$(DESTDIR)$(PREFIX)/share/man/man3/"
	mkdir -p "$(DESTDIR)$(PREFIX)/share/man/man8/"
	@$(foreach l,$(LICS),install '../$l' '$(DESTDIR)$(PREFIX)/share/doc/tlspool/' && ) echo Installed license documents
	@$(foreach d,$(DOCS),install '$d' '$(DESTDIR)$(PREFIX)/share/doc/tlspool/' && ) echo Installed technical documentation
	@$(foreach m,$(MAN8),install 'man/$m.man' '$(DESTDIR)$(PREFIX)/share/man/man8/$m.8' && ) echo Installed man page section 8
	@$(foreach n,$(MAN3),install 'man/$n.man' '$(DESTDIR)$(PREFIX)/share/man/man3/$n.3' && ) echo Installed man page section 3
	@echo '#'
	@echo '# You may need to run makewhatis or similar to update manual page caches'
	@echo '#'

uninstall:
	@$(foreach m,$(MAN3),rm -f '$(DESTDIR)$(PREFIX)/share/man/man3/$m.3' && ) echo Uninstalled man page section 3
	@$(foreach m,$(MAN8),rm -f '$(DESTDIR)$(PREFIX)/share/man/man8/$m.8' && ) echo Uninstalled man page section 8
	@$(foreach d,$(DOCS),rm -f '$(DESTDIR)$(PREFIX)/share/doc/tlspool/$d' && ) echo Uninstalled technical documentation
	@$(foreach l,$(LICS),rm -f '$(DESTDIR)$(PREFIX)/share/doc/tlspool/$l' && ) echo Uninstalled license documents
	rmdir --ignore-fail-on-non-empty "$(DESTDIR)$(PREFIX)/share/doc/tlspool/"

clean:
	@echo -n

