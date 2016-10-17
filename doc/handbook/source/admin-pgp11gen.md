Generating PGP keys from PKCS \#11 keys
=======================================

>   *Even if it makes a lot of sense to create PGP keys with PKCS \#11 top
>   protect the private half, it is suprisingly difficult with off-the-shelf
>   open source software components.  But for the TLS Pool it is incredibly
>   useful as an alternative to (server) X.509 Certificates, so we provide
>   tooling to help you get going.*

The tool `pgp11_genkey` is generic in nature, and can be used outside of the TLS
Pool.  It is just included to be sure that such a tool is available to the users
of the TLS Pool.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: pgp11_genkey provider privkey userid outfile.pgp
 - provider    is a path to a PKCS #11 service library
 - privkey     is a PKCS #11 private key URI from that provider [RFC7512]
 - userid      is a (quoted) PGP UserID like 'User Name <user@email.dom>'
 - outfile.pgp is a filename for storage of the (binary) PGP public key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The essential task of this utility is to transform a PKCS \#11 private key
(perhaps created with GnuTLS’ `certtool(1)`) into an OpenPGP public key.  The
parameters are as follows:

-   `provider` points to the PKCS \#11 library, and may be obtained as
    `$(tlspool-configvar -c /etc/tlspool.conf pkcs11_path)` to align it with the
    TLS Pool configuration

-   `privkey` refers to the PKCS \#11 key using a `pkcs11:` URI; your key
    generator is likely to output this data; we stored it in the `$P11OBJ`
    variable in our [key generation procedure](setup-srvpgp.html)

-   `userid` is at least a form `<domain.name>` or `<user@domain.name>`,
    although the embellishment with a descriptive name is certainly welcomed by
    anyone but the TLS Pool

-   `outfile.pgp` is an output file holding the public key in binary format,
    which is a default because it happens to serve the TLS Pool for [loading
    OpenPGP keys](setup-srvpgp.html) into the [local credentials
    database](tool-getset.html)

A small warning about Fingerprints
----------------------------------

It is important to understand that the generation of a public key involves time
stamping it, and that this timestamp is part of the creation of a fingerprint.
So, if you run this routine twice, you could use the same private/public keys,
but end up with different PGP fingerprints.  For this reason, the produced
public key is useful to store well for later reproduction.  There is no reason
why this could not be in a public-facing service such as a PGP key server, of
course.

Can this mechanism of differing fingerprints help with the concealment of
matching key pairs?  Hardly, I’d say.  It is trivial to find out that the keys
match, and so that the identities belong together.  There are [good
examples](http://pgp.science.uu.nl) of overviewing the entire PGP key set, so
the size of the PGP world is not any protective measure either.

We will use this in our upcoming
[IdentityHub](http://internetwide.org/blog/2016/06/24/iwo-phases.html) phase,
however.  When we create a low-cost / key-sharing
[alias](http://internetwide.org/blog/2015/04/23/id-3-idforms.html) or perhaps
allow remote users to create a local name for their list membership to represent
their [carried-in
identity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html), we are
likely to create new spin-offs from the key material, to which we simply add a
new identiy.  Note that this is the light-weight alias, where the purpose is not
to conceal relations between identities (and where not need arises to login
separately).

 
