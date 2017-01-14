DESTDIR ?= 
PREFIX ?= /usr/local/ 
BUILDDIRS=src lib tool pulleyback doc test

.PHONEY: all install clean distclean

# making LIBS/CFLAGS available in all sub-make files
PKG_CONFIG ?= pkg-config
KRB_CONFIG ?= krb5-config
export GNUTLS_CFLAGS   = $(shell $(PKG_CONFIG) --cflags gnutls)
export GNUTLS_LIBS     = $(shell $(PKG_CONFIG) --libs   gnutls)
export GNUTLS_CFLAGS  += $(shell $(PKG_CONFIG) --cflags gnutls-dane)
export GNUTLS_LIBS    += $(shell $(PKG_CONFIG) --libs   gnutls-dane)
export P11KIT_CFLAGS   = $(shell $(PKG_CONFIG) --cflags p11-kit-1)
export P11KIT_LIBS     = $(shell $(PKG_CONFIG) --libs   p11-kit-1)
export TASN1_CFLAGS    = $(shell $(PKG_CONFIG) --cflags libtasn1)
export TASN1_LIBS      = $(shell $(PKG_CONFIG) --libs   libtasn1)
export QUICKDER_CFLAGS = $(shell $(PKG_CONFIG) --cflags quick-der)
export QUICKDER_LIBS   = $(shell $(PKG_CONFIG) --libs   quick-der)
export KERBEROS_CFLAGS = $(shell $(KRB_CONFIG) --cflags)
export KERBEROS_LIBS   = $(shell $(KRB_CONFIG) --libs)

# these LIBS are not provided by pkg-config so we need them in a way the OS can override them with an 'export' from a shell
ifndef UNBOUND_LIBS
export UNBOUND_LIBS="-lunbound"
endif

ifndef BDB_LIBS
export BDB_LIBS="-ldb"
endif

ifndef LDAP_LIBS
export LDAP_LIBS="-lldap"
endif

ifndef LDNS_LIBS
export LDNS_LIBS="-lldns"
endif

ifndef SYSTEMD_LIBS
export SYSTEMD_LIBS="-lsystemd-daemon"
endif

all:
	@$(foreach dir,$(BUILDDIRS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(dir)' all && ) echo Built all
	@echo '#'
	@echo '# NOTE: You may need to "make testdata" for some tool/* programs'
	@echo '#'

install: all
	@$(foreach dir,$(BUILDDIRS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(dir)' install && ) echo Installed

uninstall:
	@$(foreach dir,$(BUILDDIRS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(dir)' uninstall && ) echo Uninstalled

clean:
	@$(foreach dir,$(BUILDDIRS),$(MAKE) DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) -C '$(dir)' clean && ) echo Cleaned
	@echo '#'
	@echo '# NOTE: Kept key material, use "make distclean" if you REALLY want to clean it'
	@echo '#'

anew: clean all

distclean: clean
	$(MAKE) -C testdata clean-pkcs11 clean-cert clean-pgp clean-db

