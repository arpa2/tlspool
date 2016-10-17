Database get and set utilities
==============================

>   *The TLS Pool rests on databases for its dynamic data, and this means that
>   entries can be changed on the fly, ready for the TLS Pool to pick them up on
>   their next use.  We provide elementary utilities to administrate these, and
>   would not be surprised or displeased if future software inspired on them
>   helps to get direct control through these databases.*

The databases used by the TLS Pool are described in detail in the [database
documentation](https://github.com/arpa2/tlspool/blob/master/doc/databases.rst).
This is explicitly intended for direct use by any applications that desire to
influence the TLS Pool in a dynamic manner.

For use from scripts, we provide the get and set utilities described below.  For
use from LDAP configurations, we provide the [PulleyBack](admin-pulleyback.html)
module that plugs into the Pulley component of SteamWorks.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbget-localid tlspool.conf [user@]fqdn type [outfile.der]
 - tlspool.conf      is the configuration file for the TLS Pool
 - user@fqdn or fqdn is a network access identifier
 - type              X.509,OpenPGP,valexp,client,server,noP11,chained
 - outfile.der       optional output file for binary encoded public data
Since the public data is stored in a binary format, it will never be printed
on stdout; in absense of outfile.der the value is simply not output.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on `localid.db` and is meant for retrieving local
credentials, selecting them with the local identity with typing and flags; and
outputting the PKCS \#11 URI on the command output and the binary credential in
a file.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbset-localid tlspool.conf [user@]fqdn type [p11priv pubdata...]
 - tlspool.conf      is the configuration file for the TLS Pool
 - user@fqdn or fqdn is a network access identifier
 - type              X.509,OpenPGP,valexp,client,server,nop11,chained
 - p11priv           is a PKCS #11 URI string for the private key
 - pubdata           is a file name    string for the public key package
The pairs of p11priv and pubdata replace the old content.  An empty list of
pairs is nothing special; it replaces the old content with zero entries.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on `localid.db` and is meant for adding and removing local
credentials, selecting them with the local identity with typing and flags; and
inputting the PKCS \#11 URI from the command line and the binary public
credential from a file mentioned on the command line.  The utility removes any
former matches with the same selection criteria.  When the PKCS \#11 URI and
public credential are not provided, this removal is all that is done; the
utility can then be used for deletion of a local credential.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbget-disclose tlspool.conf selector
 - tlspool.conf      is the configuration file for the TLS Pool
 - selector              is a matcher for remote peer identities
The selector may take the following forms:
 - domain      matches remote peer DoNAI  completely but    with no username
 - .domain     matches remote peer DoNAIs ending in .domain with no username
 - .           matches any remote peer                      with no username
 - user@domain matches remote peer DoNAI  with the username given
 - @domain     matches remote peer DoNAIs with any username
 - @.domain    matches remote peer DoNAIs with any username ending in .domain
 - @.          matches remote peer DoNAIs with any username and any domain
The command walks all the way from the selector to its most abstract form, and
shows which entries exist in the disclose.db; it then picks the one that the
TLS Pool would use and prints the localid values for that one.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on `disclose.db` and is meant to retrieve information about
disclose of local credentials to remote peers *when using TLS in client mode*.
The tool will make a concrete-to-abstract search through the keys, which are not
full-blown [DoNAIs](http://donai.arpa2.net) but, instead, [DoNAI
Selectors](http://donai.arpa2.net/selector.html).  Matches may propose one or
more local identities, and are indeed keys for use with the `localid.db` where
they help to retrieve the adjoining credentials.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbset-disclose tlspool.conf selector [[user@]domain...]
 - tlspool.conf      is the configuration file for the TLS Pool
 - selector              is a matcher for remote peer identities
 - user@domain or domain is a local client network access identifier
The list of client identities replaces the old list.  An empty list is nothing
special; it replaces the old content with zero entries.
The selector may take the following forms:
 - domain      matches remote peer DoNAI  completely but    with no username
 - .domain     matches remote peer DoNAIs ending in .domain with no username
 - .           matches any remote peer                      with no username
 - user@domain matches remote peer DoNAI  with the username given
 - @domain     matches remote peer DoNAIs with any username
 - @.domain    matches remote peer DoNAIs with any username ending in .domain
 - @.          matches remote peer DoNAIs with any username and any domain
When multiple selectors match a remote DoNAI, only the most concrete applies.
When no selector matches a remote DoNAI, the default policy is to reject.
An empty [[user@]domain] list is nothing special; it removes old content.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on `disclose.db` and is meant to update the information about
disclose of local credentials to remote peers *when using TLS in client mode*.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbget-trust tlspool.conf flags aabbccdd [outfile.bin]
 - tlspool.conf is the configuration file for the TLS Pool
 - flags        selection of x509,pgp,revoke,pinned,client,server,notroot
 - aabbccdd     is an anchor's key in hexadecimal notation
 - outfile.bin  optional output file for binary encoded anchor data
Since the anchor data is stored in a binary format, it will never be printed
on stdout; in absense of outfile.bin the value is simply not output.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on the `trust.db` and is meant to retrieve information about
trust to be placed into remote credentials by the TLS Pool.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Usage: tlspool-dbset-trust tlspool.conf flags aabbccdd valexp [infile.bin]
 - tlspool.conf is the configuration file for the TLS Pool
 - flags        selection of x509,pgp,revoke,pinned,client,server,notroot
 - aabbccdd     is an anchor's key in hexadecimal notation
 - valexp       is a validation expression for this entry
 - infile.bin   optional input file with binary encoded anchor data
When the infile.bin argument is absent, the corresponding entry is deleted.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This utility works on the `trust.db` and is meant to update information about
trust to be placed into remote credentials by the TLS Pool.
