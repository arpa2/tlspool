
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
	for l in $(LICS); do install "../$$l" "${PREFIX}/share/doc/tlspool/"; done
	for d in $(DOCS); do install "$$d" "$(PREFIX)/share/doc/tlspool/"; done
	for m in $(MAN8); do install "man/$$m.man" "$(PREFIX)/share/man/man8/$$m.8"; done
	for m in $(MAN3); do install "man/$$m.man" "$(PREFIX)/share/man/man3/$$m.3"; done

uninstall:
	for m in $(MAN3); do rm -f "$(PREFIX)/share/man/man3/$$m.3"; done
	for m in $(MAN8); do rm -f "$(PREFIX)/share/man/man8/$$m.8"; done
	for d in $(DOCS); do rm -f "$(PREFIX)/share/doc/tlspool/`basename $$d`"; done
	for l in $(LICS); do rm -f "$(PREFIX)/share/doc/tlspool/$$l"; done
	rmdir --ignore-fail-on-non-empty "$(PREFIX)/share/doc/tlspool/"

clean:
	@echo -n

