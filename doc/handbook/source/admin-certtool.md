The certtool from GnuTLS
========================

>   *We recommend the certtool from GnuTLS because of its PKCS \#11 support.*

Most people have gotten used to the OpenSSL tools, for generation of keys and
certificate requests, or even to run their own certificate authority.

Since the TLS Pool relies on PKCS \#11, we instead advise the use of
[certtool](http://www.gnutls.org/manual/html_node/certtool-Invocation.html), as
supplied with GnuTLS.  It is well-versed in the use of PKCS \#11.

Note however that it should be possible to [setup PKCS \#11 with
OpenSSL](https://github.com/OpenSC/engine_pkcs11) as well.
