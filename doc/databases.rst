Databases for use with the TLS Pool
===================================

*The TLS Pool can be configured with a number of local key/value databases of
the DBM variety.  These databases are fast, they scale up to large deployments
and they can be filled independently of the TLS Pool.*


Most databases use a Domain-or-Network-Access-Identifier or DoNAI_ as a key.
This is a domain name or a user at a domain name.
The username may be case sensitive
according to local policy, but by default it is not.  Domain names are never
case sensitive.

Case insensitive DoNAIs are mapped to lowercase.  User-(inter)facing programs
should either be setup to handle usernames with case sensitivity, or ask the
user if they present a username with uppercase characters in them.  Domain
names are always mapped to lowercase.

.. _DoNAI : http://donai.arpa2.net

Another notation used in the databases is the `PKCS #11 URI`_, which is an
upcoming standard method of describing PKCS #11 tokens such as HSMs and
USB key-encapsulating sticks through labelling; in addition, objects such
as private keys and public keys on such tokens can be described with a
PKCS #11 URI.  Note that it is a URI and not a URL; that is, the TLS Pool
must still be configured to find one or more tokens to look into for
finding the URI-specified values.

.. _`PKCS #11 URI` : https://tools.ietf.org/html/rfc7512

The TLS Pool offloads memory caching to its backend databases, which should
be good at it, and at the same time be able to pickup on changes made by
other processes.  In other words, TLS Pool does quite a few queries on its
databases and relies on the database to respond quickly with clever caching.

The choice of database is based on the importance of scaling and efficiency,
and has fallen on the simple but highly efficient key-value databases known
as the `Berkeley DB`_, originally from Sleepycat software and later purchased
and extended by Oracle.

.. _`Berkeley DB` : http://docs.oracle.com/cd/E17076_04/html/index.html

A few advanced concepts involved in the Berkeley DB are of importance to
the TLS Pool:

  * The absense of an interpreted query language and the default semantics of single-key lookup are a much better match to the fixed requirements of the TLS Pool than an SQL interface;
  * `Secondary databases`_ provide alternate keys to lookup entries in existing databases and even support `join semantics`_;
  * `Transactions`_ ensure the invisibility of half-way results during changes to a database; for example, between removal of an old identity and adding a new one, the identity does not disappear for a glitch of a second;
  * `Replication`_ permits the TLS Pool to run on multiple nodes at once, thus scaling up with a shared memory between nodes.  It also supports a model where a remote entity writes identities and credentials into a database that is replicated to the node used by the TLS Pool.

.. _`Secondary databases` : http://docs.oracle.com/cd/E17076_04/html/gsg/C/indexes.html
.. _`join semantics` : http://docs.oracle.com/cd/E17076_04/html/gsg/C/joins.html
.. _`Transactions` : http://docs.oracle.com/cd/E17076_04/html/gsg_txn/C/index.html
.. _`Replication` : http://docs.oracle.com/cd/E17076_04/html/gsg_db_rep/C/index.html


These databases may be modified while the TLS Pool is using them, and updates
should be dynamically incorporated.  As a result, the TLS Pool daemon can
continue to run during updates to the identities serviced.


For experimental purposes, the ``testdata`` directory of the source code
holds simple examples; it even includes binary databases that seem to work
on most (if not all) AMD64-based operating platforms; the ``tool``
directory of the source code holds tools to manipulate several of the databases
described herein.


Local identity database
-----------------------

Local identities are stored in a database named, by default, ``localid.db``.

It is an explicit purpose to support large numbers of identities in a scalable
and highly dynamic manner; therefore, the TLS Pool will not cache local
identities in memory like a classical web server might.  Instead, it relies
on the database to do any memory caching of even oft-used identities, and to find
less popular identities with great speed.  The BerkeleyDB was specifically
selected because it ranks well on these issues.

This is a duplicate hash database; one key may hold multiple values.

**Key** is the DoNAI of the local user.

**Values** each are a binary composition of the following elements:

  * A 32-bit value in network byte order, containing ``LID_xxx`` flags;
  * A `PKCS #11 URI`_ referencing the private key for the identity;
  * A single byte value ``0x00``
  * A sequence of bytes composing a public value in binary representation.

Note that the public value differs between key uses; the following forms have
been defined at this time:

  * for ``LID_TYPE_X509`` it is a DER-encoded X.509 certificate without chain that matches the NAI in ``Email`` and/or ``commonName`` fields;  However, when ``LID_CHAINED`` is additionally specified, in which case a chain of certificates to be deliverd to the remote peer may be concatenated to the X.509 certificate.
  * for ``LID_TYPE_PGP`` it is a binary-encoded public key packet containing:
     - One public key
     - One User ID holding at least the DoNAI between < and >
     - A self-signature binding this User ID to the public key
     - Possibly added signatures binding this User ID to the public key
     - One encryption subkey
     - A self-signature binding the encryption subkey to the public key
  * for ``LID_TYPE_KRB5``, an empty public value is currently the only
    form being processed; it indicates that the local identity should be read
    as a Kerberos identifier, after mapping the domain name to all uppercase,
    and that the PKCS #11 URI directly references the Kerberos password (which
    means that PKCS #11 is only used to carry an exportable password, though
    usually with PIN-based encryption on the stored password).
    Future versions of ``LID_TYPE_KRB5`` will skip such empty entries and
    instead parse more elaborate public values.  What will be in there depends
    on such choices as whether some form of
    [pseudonymity](https://datatracker.ietf.org/doc/draft-vanrein-kitten-krb-pseudonymity/)
    is available for Kerberos, and whether or not PKCS #11 can be used
    [underneath Kerberos](https://github.com/arpa2/kerberos-pkcs11)
    instead of next to it.
  * no form has been settled for ``LID_TYPE_SRP`` yet.  We will probably be able to use our own flavour, [SRP #11](http://github.com/arpa2/srp-pkcs11), going through PKCS #11 on the client side.  The identity will then probably be the username, salt (including pinning information), DH public key and a PKCS #11 URI of a DH private key (consisting of exponent, base, modulus).

There are a few more flags in the initial word of an entry:

  * ``LID_ROLE_CLIENT`` is set if this entry can be used in TLS clients;
  * ``LID_ROLE_SERVER`` is set if this entry can be used in TLS servers;
  * Both may be set, and indeed this may be common for OpenPGP keys.

A special form of the localid entry is for an validation expression that
may be applied to the local identity represented in the key; this is
setup as ``LID_TYPE_VALEXP``.  Its PKCS #11 string is abused to hold the
validation expression, and it has the following 0x00 byte as a C-style
string terminator.  There is no binary value stored for this type of entry.
Note that the same validation expression applies to all the forms of  
identifying as the local identity.  When this entry is absent, it is
considered to permit anything, as were the validation expression "1".  


Identity disclosure database
----------------------------

The default name of this database is ``disclose.db``.

The purpose of this database is to regulate the disclosure of a local identity
to remote entities.  Given that the server presents its identity before the
client in TLS, the use of this database is specific to clients.

Whether disclosure is permitted depends on the server name accessed from the
TLS client.  This cannot be influenced by a rogue server, but something else
may interfere with privacy, namely that the client certificate is sent before
the server has been authenticated, and before encryption is activated.  Only
servers that re-negotiate TLS to request a certificate have gone through
those phases, and then privacy is complete.  Unfortunately this behaviour
cannot be enforced by a TLS client without breaking the TLS protocol.

This is a secondary database that associates with the local identity database.

**Key**
is a `DoNAI Selector`_ for remote peers; this may either describe a single
remote peer name, or capture multiple.
The TLS Pool will look for the closest match possible, by
gradually breaking down a remote peer name until it finds the key in the
database.  Take note that there are different hierarchies for DoNAIs that
do and don't carry an `@` sign.  In situations where a domain may speak on
behalf of users, the domain is considered prefixed with the `@` in a match
against a `user@domain.name` style DoNAI.

If no matching key is found, or if local identity is explicitly set but
it does not appear as a value under a key, then the TLS Pool will try to
send out a question to the user, asking what local identity must be shown;
when the subsequent TLS negotiations succeed with this, the identity will
be added to the identity disclosure database.  If no user program is
listening for such inquiries, then no identity is offered to the remote.

.. _`DoNAI Selector` : http://donai.arpa2.net/selector.html

**Value**
is the key of the local identity database, so it is a DoNAI.
When multiple values have been added under the same key, then each is
considered in order; left to its own devices the TLS Pool would pick the
first, but when an external "lidentry" tool has registered to be called
back even in the presence of a database entry, then all the
entries found will be reported and a choice can be made by that tool.


**TODO:** We should probably also define a validation expression in
the disclosure database, to mark restrictions on contact with those
particular remote selections.  If that is done, we should also apply
this validation expression to the case where the remote is a client!
We might terminate the first entry with a NUL character to indicate
a validation expression, for instance; that is invalid DoNAI syntax.


Trust database
--------------

The default name of this database is ``trust.db``.

The purpose of this database is to establish trust in credentials such as
certificates or Kerberos principal names.  It may hold several methods to
establish this trust:

  * Trust anchors, notably X.509 root certificates and trusted OpenPGP public keys
  * X.509 certificate chains of OpenPGP public key paths leading to a trust anchor
  * Pinned ending time stamps (must-change and may-change, if provided)
  * Withdrawal descriptors to express explicit loss of trust
  * Validation requirements for anything subordinate this entry

Entries in this database are accessible to parties other than the TLS Pool;
this means that it would be possible to control the TLS Pool centrally by
a provisioning mechanism that ends up writing into this database.  This even
means that centralised credential pinning is supported, to relieve individual
users falling under central management.

The origin of the data need not be manually administered.  Protocols such
as OCSP or DANE could be used to retrieve information to be automaically
inserted into this database.  This might be done from a central location,
and both simplify and speedup the management of provisioned setups.

**Key** is a binary representation of data to be found:

  * The `AuthorityKeyIdentifier` [Section 4.2.1.1 of RFC 5280] that must
    be used in all CA-signed certificates other than a root certificate.
  * The 64-bit v4 key ID [Section 12.2 of RFC 4880] of a PGP public key.
  * The SHA-256 fingerprint of a pinned endpoint credential.

**Values** each are a binary composition of the following elements:

  * A 32-bit flag field in network-byte order,
    including the type of material represented in the key, according to
    the database entry at hand (each type has separate entries), one of the
    flags is used to indicate revocation rather than confirmation;
  * A NUL-terminated string holding a validation expression (the least of
    which would be "1", or 0x30 0x00); this is meaningful for signing entries;
  * The parameters for the given type; usually, a credential to use for
    validation:

      - For X.509 root certificates, a CA root key; intermediate keys are
        assumed to have been passed from remote to local.
      - For PGP keys, a trusted signing key in PGP public key transport
        format; these may be looked up with key IDs of Issuer subpackets found
        in signatures; note that only one-level PGP signing is supported,
        but PGP's potential diversity of signers is fully supported.
      - There are revocation entries (whose validation expression is ignored)
        with times for an update (and the next) and a sequence of certificate
        serial numbers.  These revocation entries are stored under the same
	key as a trusted entry, after this principal trusted entry.
      - For pinning, there are a few flavours; a 32-bit type field defines
        the type of data.  Since a secure hash has matched, there is no
        further mention of the unfolded pinning information.  Following is a
        NUL-terminated string holding the remote identity established with
        the pinned end entity credential.

