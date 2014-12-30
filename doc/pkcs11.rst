-----------------------------------
TLS Pool Key Repository in PKCS #11
-----------------------------------

*The TLS Pool makes a deliberate choice to separate the management of
private keys from the TLS Pool, which in turn is isolated from application
programs that rely on TLS.  PKCS #11 is used as the key repository, and is
the ultimate source for keys, both public and private.*


Quick Intro to PKCS #11
=======================

The purpose of PKCS #11 is to provide a generic API for key-based operations;
implementations range from software to hardened hardware bastions.  Behind the
PKCS #11 API, private keys are available; but the API can forbid their export
and limit use to signing and decryption operations.

Many implementations of PKCS #11 connect to a device over a network, but there
are also very useful implementations based on USB tokens.  The first may be
suitable for servers, the second for clients operating (say) a laptop.  Another
variation that is popular on software is to use a software HSM, possibly over
a network connection so it can run in a secure environment.


How we like to connect to PKCS #11
==================================

The best possible protection of private keys can be achieved by locating
the private keys on another system than applications.  The customary way
to login to PKCS #11 is through a (fixed) PIN, but we see an extra option.

Given that PKCS #11 is a library, it is loaded into an application's
process space.  This means that remote access is indeed a good idea.
But it also means that the environment of the user running an
application is available; specifically, one may access key daemons for
OpenSSH, OpenPGP and Kerberos5.  In cases where the TLS Pool runs under
control of a user, this is still true.

We prefer to use one of these mechanisms to connect securely to a remote
resource; perhaps using an OpenSSH tunnel or a GSS-API protocol based
on Kerberos5.  That means that strong cryptography under control of the
user helps to protect access to the PKCS #11 repository.  Especially
Kerberos5, with its ability of Constrained Delegation is powerful in
this sense, because it could even be used in a controlled manner by
remote services when a user accesses them.

The PIN hardly adds anything in these situations, and since it is usually
stored in files, that is probably a good thing.  The one thing it can be
very useful for, is for access control.  So, knowing the PIN defines a
view, or a set of objects that can be seen from the session after login.


Use of PKCS #11 within ARPA2
============================

The PKCS #11 API has another useful property, namely that of a key repository.
Different parties may connect to it, which means that key management can be
separated from using keys.

Key management is the process of creating keys, replacing them when they are
about to expire, and purging them when they have gone out of use.  It may
also involve backup and recovery mechanisms.

Key management is an important part of ARPA2's identity management.  Keys
will created rather lightly, in pursuit of strong security mechanisms and
their straightforward use by end-users.  When keys are withdrawn, their
private keys may be withdrawn before certificates are.

None of these key management issues are a concern to the TLS Pool, which
only needs to lookup keys and use them.  It simply assumes to find objects
that follow a suitable format to work with.  These formats are specified
below.

**TODO:** Sessions may provide object lists that are not up to date.  This
implies a need to regularly reconnect to the PKCS #11 API.


Assumed key presence in PKCS #11
================================

The TLS Pool needs to be able to access keys in PKCS #11, and it needs to
search for them.  To facilitate that, certain expectations need to be
fulfilled.

Most protocols need to access objects based on their name, which usually
is a NAI [RFC 4282].  The NAI may either be a domain name, such as
``example.com``, or it may prefix a username and an at symbol, as in
``john@example.com``.

Extracting identity mappings
----------------------------

Since PKCS #11 does not have API methods to search for patterns, but only
to search for exact matches, the format of several of the identities
should represent the NAI as directly as possible.  At the same time, they
need to be true to the nature of a given certificate type, which is often
very specific about representation.

These conflicts can only be overcome by iterating over the full contents
of the PKCS #11 store, and collecting an index of search results.  The
key of such an index would be the NAI, and the values stored would reveal
the various certificate forms and their ``CKA_LABEL`` and ``CKA_ID``
fields.

Even if the derivation of such an index is less optimal than having it
delivered over an external interface, it still amounts for much more
stability to retain the singularity of the information source.  Moreover,
the PKCS #11 session specification states that updates made in other
sessions may not necesssarily show up in sessions that were opened prior
to such changes.  In other words, a session would have to be reopened
to refresh a PKCS #11 application.

**TODO:** Update policy, or notifications?

The local identity mapping comes down to:

*  The NAI serves as a key, mapped to lowercase where parts are
   case-insensitive; this means that the entire NAI is mapped to lowercase,
   since usernames are also case-insensitive under ARPA2.  The NAI is derived
   from the available attributes as specified below.
*  The value is basically a search structure fit for PKCS #11.  Part of it
   is the ``CKA_ID`` attribute that is also used to locate the private or
   secret key.  Typing information that helps to determine the kind of public
   key information is included in the value.
*  **Note:** a Key handle is session-specific, but might be stored nonetheless,
   if sessions overlap and refreshes take place as needed.  In that case, the
   value must incorporate the session handle.
*  **TODO:** We could also store the ``CKA_VALUE`` with the certificate, so
   there would be no need to search?

In ASN.1 notation, the following data is encoded in BER (actually, DER) in
the value part::

	pubkeyIDset ::= SET OF pubkeyID;
	pubkeyID ::= SEQUENCE {
		sessionOpened TIMESTAMP;
		template pubkeyTemplate;
	}
	pubkeyTemplate ::= SEQUENCE OF pubkeyAttr;
	pubkeyAttr ::= SEQUENCE {
		attrType INTEGER;
		attrValue OCTETSTRING;
	}

This structure may be stored in memory, on disk or in a key-value database
that suffers from amnesia.  The ``SET`` defines alternatives; it is possible
that there are none, which may be considered a cached not-found value.  The
``sessionOpened`` captures the time that the oldest possible time at which
the session's current objects were established.

How much memory would this consume?  Consider a server for a large number
of identities, say 100,000.  Identities of 1 kB each would lead to 100 MB
of storage, not much for such a work load -- certainly not because there
is such a thing as swap space that can easily handle that load for a server
with so many identities.  At some point, we might consider the store to be
a cache.  Note that it is always possible to retain public object identifiers,
which amount to much less storage space; 4 bytes times 100,000 makes for
just 500 kB.


Easy start: Initial coding
--------------------------

Initially, the code will traverse over all objects for every signing operation.
This is clearly bad for performance, but the iteration over the session and
subsequent selection of suitable objects is going to be the same as for
building up the cache.


Key presence assumed for X.509
------------------------------

An X.509 certificate and private key are paired by a matching ``CKA_ID``
field.  This field usually holds a hash of a key; in general, the field
is assumed sufficiently long and scattered over its domain that only a
single private would be found for a given ``CKA_ID`` value.  The opposite
need not be true; multiple X.509 certificates may share the same ``CKA_ID``
value; these would refer to the same private key object.

To find a certificate, the following attributes are combined:

* ``CKA_CLASS`` must be set to ``CKO_CERTIFICATE``
* ``CKA_CERTIFICATE_TYPE`` must be set to ``CKC_X_509``
* ``CKA_SUBJECT`` must be set to ``cn=<NAI>`` where ``<NAI>`` represents
  the NAI syntax as a ``commonName`` attribute.

**TODO:** The NAI is incompatible with the PKCS #11 text, "DER-encoding of the
certificate subject name", so we will need a translation.  Regex or DB, or both?

For all certificate objects that match, the following attributes are
additionally retrieved and used in further processing:

* ``CKA_START_DATE`` and ``CKA_END_DATE``, when available, are checked and
  lead to removal of the certificate object because it is invalid.  Deletion
  of objects is left to key management, but the TLS Pool should not act
  stupidly, of course.
* ``CKA_ID`` is extracted as a reference to the private key.  It is assumed
  to locate a single private key only, but multiple public key representations
  may point to one private key.
* ``CKA_URL`` and ``CKA_VALUE`` are downloaded to get to the certificate's
  binary form.  If ``CKA_VALUE`` is absent, the ``CKA_URL`` is used instead.

The result of this process is a list of X.509 certificates that can be used
to represent a local identity.  The list may be empty, which means that there
are no alternatives available.  It is up to the TLS Pool what that means.
When multiple alternatives are available, they should all be presented or
used.

At some point, there may be a need to use the private key belonging to the
X.509 certificate.  This is where the ``CKA_ID`` is used.  It is assumed
that any protocol that offers multiple options to a peer will receive an
indication of the peer's choice, in a way that can help to lookup the
``CKA_ID`` belonging to the choice.

To locate precisely one private key, the following attributes are used:

* ``CKA_CLASS`` must be set to ``CKO_PRIVATE_KEY``
* ``CKA_ID`` must match the ``CKA_ID`` from the X.509 certificate object.

The search must find exactly one private key; this is checked by attempting
to find multiple keys, and validating that precisely one is found.


Key presence assumed for OpenPGP
--------------------------------

See `OpenPGP keys in PKCS #11`_ for specifications.

.. _`OpenPGP keys in PKCS #11` : http://openfortress.nl/doc/spec/pgp-in-pkcs11/

**TODO:** This is implemented in SoftHSMv2, but not broadly yet.
The OpenPGP key representation is however a non-disruptive vendor extension
that can easily be introduced into each PKCS #11 implementation.  In a later
phase, we assume this specification to be standardised.

OpenPGP keys support multiple identities for a single public key.  This
is compatible with the permitted practice that multiple public objects point
to one private object.

The UserID for OpenPGP keys are informally defined, and usually hold a
form like ``John Smith <john@example.com>`` and that is difficult to match
accurately with a PKCS #11 search if we only have a NAI [RFC 4282] available.
For that reason, the TLS Pool assumes that the name is absent, and it will
simply look for ``<john@example.com>`` or ``<@example.com>`` if only a domain
name is defined.  Note that the ``@`` is retained in the latter form.

**TODO:** As with X.509, we could consider a mapping from a NAI to a
UserID (of any form) and possible to a ``KEY_ID``.


Key presence assumed for Secure Remote Passwords
------------------------------------------------

There is no specification for incorporation of SRP into PKCS #11, but the
specification can handle secret keys, and introduce their values in
hash calculations.  This means that the secret (known as the password in
SRP) is not needed outside of the PKCS #11 context.

Salt and Verifier can be stored in PKCS #11 data objects.

**TODO:** Define.

