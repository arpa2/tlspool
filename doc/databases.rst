Databases for use with TLS Pool
===============================

*TLS Pool can be configured with a number of local key/value databases of
the DBM variety.  These databases are fast, they scale up to large deployments
and they can be filled independently of the TLS Pool.*


Most databases use a `Network Access Identifier`_ or NAI as a key.  This is a
domain name or a user of a domain name.  The username may be case sensitive
according to local policy, but by default it is not.  Domain names are never
case sensitive.

Case insensitive NAIs are mapped to lowercase.  User-(inter)facing programs
should either be setup to handle usernames with case sensitivity, or ask the
user if they present a username with uppercase characters in them.  Domain
names are always mapped to lowercase.

.. _`Network Access Identifier` : http://tools.ietf.org/html/rfc4282

Another form used in the databases is the `PKCS #11 URI`_, which is an
upcoming standard method of describing PKCS #11 tokens such as HSMs and
USB key-encapsulating sticks through labelling; in addition, objects such
as private keys and public keys on such tokens can be described with a
PKCS #11 URI.  Note that it is a URI and not a URL; that is, the TLS Pool
must still be configured to find one or more tokens to look into for
finding the URI-specified values.

.. _`PKCS #11 URI` : https://tools.ietf.org/html/draft-pechanec-pkcs11uri

The TLS Pool offloads memory caching to its backend databases, which should
be good at it, and at the same time be able to pickup on changes made by
other processes.  In other words, TLS Pool does quite a few queries on its
databases.

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
  * `Replication`_ permits TLS Pool to run on multiple nodes at once, thus scaling up with a shared memory between nodes.

.. _`Secondary databases` : http://docs.oracle.com/cd/E17076_04/html/gsg/C/indexes.html
.. _`join semantics` : http://docs.oracle.com/cd/E17076_04/html/gsg/C/joins.html
.. _`Transactions` : http://docs.oracle.com/cd/E17076_04/html/gsg_txn/C/index.html
.. _`Replication` : http://docs.oracle.com/cd/E17076_04/html/gsg_db_rep/C/index.html


These databases may be modified while the TLS Pool is using them, and updates
should be dynamically incorporated.  The resulting daemon can continue to run
in spite of updates to the identities serviced.


For experimental purposes, the ``testdata`` directory of the source code
holds simple examples; the ``tool`` directory of the source code holds
tools to manipulate several of the databases described herein.


Local identity database
-----------------------

Local identities are stored in a database named, by default, ``localid.db``.

It is an explicit purpose to support large numbers of identities in a scalable
and highly dynamic manner; therefore, the TLS Pool will not cache local
identities in memory like a classical web server might.  Instead, it relies
on the database to do any memory caching of oft-used identities, and to find
less popular identities with great speed.  The BerkeleyDB was specifically
selected because it ranks well on these issues.

This is a duplicate hash database; one key may hold multiple values.

**Key** is the NAI of the local user.

**Value** is a binary compositions of the following elements:

  * A 32-bit value in network byte order, containing ``LID_xxx`` flags;
  * A `PKCS #11 URI`_ referencing the private key for the identity;
  * A single byte value ``0x00``
  * A sequence of bytes composing a public value in binary representation.

Note that the public value differs between key uses; the following forms have
been defined at this time:

  * for ``LID_TYPE_X509`` it is a DER-encoded X.509 certificate without chain that matches the NAI in ``Email`` and/or ``commonName`` fields;
  * for ``LID_TYPE_PGP`` it is a binery-encoded public key packet containing:
     - One public key
     - One User ID holding at least the NAI between < and >
     - A self-signature on this User ID
     - Possibly added signatures on this User ID
     - One encryption subkey
     - A self-signature on the encryption subkey
  * no forms have been settled for ``LID_TYPE_SRP`` and ``LID_TYPE_KRB5`` yet.

There are a few more flags in the initial word of an entry:

  * ``LID_ROLE_CLIENT`` is set if this entry can be used in TLS clients;
  * ``LID_ROLE_SERVER`` is set if this entry can be used in TLS servers;
  * Both may be set, and indeed this will be common for OpenPGP keys.


Identity disclosure database
----------------------------

The default name of this database is ``disclose.db``.

The purpose of this database is to regulate the disclosure of a local identity
to remote entities.  Given that the server presents its identity before the
client in TLS, the use of this database is specific to clients.

Whether disclosure is permitted is based on the server name accessed from the
TLS client.  This cannot be influenced by a rogue server, but something else
may interfere with privacy, namely that the client certificate is sent before
the server has been authenticated, and before encryption is activated.  Only
servers that re-negotiate TLS to request a certificate have gone through
those phases, and then privacy is complete.  Unfortunately this behaviour
cannot be enforced by a TLS client without breaking the TLS protocol.

This is a secondary database that associates with the local identity database.

**Key**
is the NAI of a remote peer, or a (partial) domain name prefixed with a dot
or ampersand.
The form that begins with a dot or ampersand matches anything ending in this
key string.  The TLS Pool will look for the closest match possible, by
gradually breaking down a remote peer name until it finds the key in the
database.

If no matching key is found, or if local identity is explicitly set but
it does not appear as a value under a key, then the TLS Pool will try to
send out a question to the user, asking what local identity must be shown;
when the subsequent TLS negotiations succeed with this, the identity will
be added to the identity disclosure database.  If no user program is
listening for such inquiries, then no identity is offered to the remote.

**Value**
is the key of the local identity database, so it is a NAI.
