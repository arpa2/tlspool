Developer Test Data
===================

Please find structures prepared for testing over here.

The old habit of static binary files is still present in historic, but
probably not worth your time anymore, even if you are on amd64.

The new approach is through a Makefile that can build up private keys in
your PKCS #11 token of choice and create certificates for them, and setup
the databases accordingly.

All this is possible thanks to the wonderful tools of p11-kit, certtool
and p11tool, which are all quite generic and quite supportive.  They made
it possible to actually create the private keys in the PKCS #11 library,
instead of importing it as we've done in the past.

Take note of tool/pgp11-genkey.c -- it may well be the first little
program to create PGP keys from a PKCS #11 stored private key, and if
not then it's never been so easy.  GnuTLS can use such keys, of course.

