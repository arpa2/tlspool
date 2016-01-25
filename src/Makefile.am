AM_CFLAGS = -pthread -I $(srcdir)/../include $(GNUTLS_CFLAGS) $(P11KIT_CFLAGS) $(BDB_CFLAGS) $(TASN1_CFLAGS)
AM_LDFLAGS = $(GNUTLS_LIBS) $(P11KIT_LIBS) $(BDB_LIBS) $(TASN1_LIBS)
sbin_PROGRAMS = tlspool
tlspool_SOURCES = daemon.c config.c manage.c service.c cache.c pinentry.c lidentry.c starttls.c donai.c remote.c error.c error.h manage.h donai.h ctlkey.c
