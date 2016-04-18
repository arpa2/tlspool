
BUILDDIRS=src lib tool doc test

.PHONEY: all install clean distclean

all:
	@$(foreach dir,$(BUILDDIRS),make -C '$(dir)' all && ) echo Built all
	@echo '#'
	@echo '# NOTE: You may need to "make testdata" for some tool/* programs'
	@echo '#'

install: all
	@$(foreach dir,$(BUILDDIRS),make -C '$(dir)' install && ) echo Installed

uninstall:
	@$(foreach dir,$(BUILDDIRS),make -C '$(dir)' uninstall && ) echo Uninstalled

clean:
	@$(foreach dir,$(BUILDDIRS),make -C '$(dir)' clean && ) echo Cleaned
	@echo '#'
	@echo '# NOTE: Kept key material, use "make distclean" if you REALLY want to clean it'
	@echo '#'

anew: clean all

distclean: clean
	make -C testdata clean-pkcs11 clean-cert clean-pgp clean-db

