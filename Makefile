
BUILDDIRS=src lib tool doc

.PHONEY: all install clean distclean

all:
	for dir in $(BUILDDIRS); do make -C "$$dir" ; done
	@echo '#'
	@echo '# NOTE: You may need to "make testdata" for some tool/* programs'
	@echo '#'

install: all
	for dir in $(BUILDDIRS); do make -C "$$dir" install ; done

uninstall:
	for dir in $(BUILDDIRS); do make -C "$$dir" uninstall ; done

clean:
	for dir in $(BUILDDIRS); do make -C "$$dir" clean ; done
	@echo '#'
	@echo '# NOTE: Kept key material, use "make distclean" if you REALLY want to clean it'
	@echo '#'

distclean: clean
	make -C testdata clean-pkcs11 clean-cert clean-pgp clean-db

