On-the-fly Signing for Proxies
==============================

>   *A vital bit of support in the TLS Pool is to service proxies through
>   on-the-fly signing or, as we sometimes call it, the “flying signer” built
>   into the TLS Pool.*

When a proxy is placed in a TLS connection, for example to filter out
privacy-assaulting content passing through, it needs to do something that is
normally frowned upon, namely play the role of a “man in the middle”.  This is
indeed only possible when the client side is configured to permit it.

The normal method of circumventing the default protection against men in the
middle is through a root certificate under which proxy certificates, whose
naming is such that the client should accept it.  Since the names of the remotes
cannot always be predicted, such as with an HTTPS\_PROXY, chances are that these
proxy certificates must be generated on the fly.

Please note: The flying signer is currently limited to connections based on
X.509 Certificates only.  This is not a strict technical limitation however; it
is merely due to lack of time implementing other mechanisms.

To setup a signing proxy, the TLS Pool must be supplied with a signing
certificate under which it can create proxy certificates on the fly.  And the
matching key to the signing certificate will be needed; protected by PKCS \#11
as always.  The signing certificate may be  a root certificate, but does not
have to be.  As long as some way exists to make it acceptable to clients,
anything is possible.

To obtain a signing certificate, proceed as for [Setting up Server
Certificates](setup-srvcert.html), but ensure the presence of the `CA` bit which
enables underlying certificates to be validated with the signing certificate in
the path.  In the `certtool` template files, this is expressed by

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Whether this is a CA certificate or not
ca
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This flag is one to be cautious about — normal certificates MUST NOT use it, but
intermediate certificates all REQUIRE it.  The flag sets the boys apart from the
men, one might say.
