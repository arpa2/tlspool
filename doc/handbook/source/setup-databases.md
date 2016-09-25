Setup: Databases
================

>   *The dynamic data used by the TLS Pool is stored in a few databases.  These
>   are simple key-to-value lookup databases, and more in detail they are
>   BerkeleyDB files.  This implementation, now owned and maintained by Oracle,
>   are not the fatest option in the world.  This reflects on the age of
>   BerkeleyDB, but so does its stability and resilience to crashes and other
>   disasters.*

The TLS Pool uses three databases, by default named in the configuration file
as:

-   `localid.db` — holding local credential / secret pairs

-   `disclose.db` — holding information on what local identities are available
    to any given remote

-   `trust.db` — holding statements of trust about remotely used credentials

These files are stored in a directory relative to the “database environment”,
usually in its parent directory.  The “database environment” contains log files
and other recovery structures.  It is generally a bad idea to remove and/or
replace the database files and/or their logs, or a part thereof.

The configuration file variables controlling the databases are:

-   `dbenv_dir ../testdata/tlspool.env` holds the location for the binary
    database file; it does not usually contain the following database files.
    The location is relative to a subdirectory of the TLS Pool’s GitHUB entry.

-   `db_localid ../localid.db` maps the [DoNAI](http://donai.arpa2.net) of a
    local identity; is that the idea?

-   `db_disclose ../disclose.db` maps remote identities (or Selectors over them)
    to one or more local identities supported.

-   `db_trust ../trust.db` anchors the trust that we place in remote identities.

The three `db_` entries are all file names relative to `dbenv_dir`, which is
setup above for developer’s optimal use.  In your installation, you probably
want to set an absolute path, like this for a system-wide install:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
dbenv_dir /var/db/tlspool/dbenv
db_localid ../localid.db
db_disclose ../disclose.db
db_trust ../trust.db
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The databases themselves are relative to the environment; they are not stored in
the environment however.  Also create the directories involved, and make them
accessible to the `daemon_user` and/or `daemon_group`:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
mkdir -p /var/db/tlspool/dbenv
chown -R tlspool:tlspool /var/db/tlspool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You do not need to prime the databases, the TLS Pool management utilities will
do this for you.  This should lead to files like these:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
-rw-r----- 1 tlspool tlspool    49152 /var/db/tlspool/localid.db
-rw-r----- 1 tlspool tlspool    49152 /var/db/tlspool/disclose.db
-rw-r----- 1 tlspool tlspool    49152 /var/db/tlspool/trust.db
-rw------- 1 tlspool root       24576 /var/db/tlspool/env/__db.001
-rw------- 1 tlspool root      204800 /var/db/tlspool/env/__db.002
-rw------- 1 tlspool root      270336 /var/db/tlspool/env/__db.003
-rw------- 1 tlspool root      163840 /var/db/tlspool/env/__db.004
-rw------- 1 tlspool root      811008 /var/db/tlspool/env/__db.005
-rw------- 1 tlspool root       49152 /var/db/tlspool/env/__db.006
-rw------- 1 tlspool tlspool 10485760 /var/db/tlspool/env/log.0000000001
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you ever need to modify the data, please use the tools provided.  You
otherwise risk damage to the databases and could end up having to replace them
completely.  The log files and databases hang together, and replacing one of
them at a time may lead to a need to dive into the details of BerkeleyDB
database management — which is powerful, but also a topic on its own.
