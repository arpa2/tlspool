Configuration Interface: Credentials & Trust
============================================

>   *The TLS Pool is open to dynamic reconfiguration.  This can be used to setup
>   matters of local credentials and trust in remote credentials.  The
>   mechanisms are a database and PKCS \#11.*

The TLS Pool reads its data from databases, and it uses PKCS \#11.  These are
sources that can process some degree of dynamicity, meaning that configuration
data, once written to these places, should be picked up by the TLS Pool on its
next use of them.  Both resource forms are capable of handling concurrent use by
the TLS Pool and external programs that modify their settings.

**Credentials** represent the local user, and this information is stored in the
local identity database, in a file that is named `localid.db` in the default
configuration file.  This file is a mapping from a local
[DoNAI](http://donai.arpa2.net) to one or more records that describes a
credential for that DoNAI.  Credentials contain some type information and flags,
but essentially form a pair of a public manifestation of the identity with a
private handle to prove the corresponding ownership.

The “public manifestation” is a binary representation such as

-   an X.509 certificate

-   an OpenPGP public key

The “private handle” is usually a `pkcs11:` URI, pointing at the concealed
object that should be used with the public manifestation.

**Credential visibility** can be established over the user interface, but it may
also be done by configuration programs.  The database with default name
`disclose.db` in the default configuration file maps remote identities to one or
more local identities that may be presented to that remote.  Both remote and
local identities take the form of a [DoNAI](http://donai.arpa2.net).  The
entries found as the result of the disclosure mapping are usually looked up in
the local identity database.

**Trust** is an explicit statement that a remote identity or something that
validates it is ultimately trusted.  Examples of trust statements include root
certificates from trusted certificate authorities and manually pinned end-user
certificates.

The database named `trust.db` in the default configuration handles trust; it
maps a binary extract form the remote credential, in a form specific to that
credential, to information about the trust relationship.

**Validation expressions** form an important part of trust statements.  These
expressions indicate which validations must be applied to a remote identity and
its credentials.  The precise implementation may vary between forms of remote
identity (for instance, X.509 certificates can work a bit different from OpenPGP
public keys).  The most generous validation expression is `1`, the least
permissive one is `0` and in between there can be many different [boolean
expressions](https://github.com/arpa2/tlspool/blob/master/doc/validation.md)
based on primitive predicates.
