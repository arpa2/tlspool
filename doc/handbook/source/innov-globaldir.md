Global Directory support
========================

>   *The TLS Pool is supportive of an LDAP Global Directory.  This means that
>   credentials can be confirmed by any domain user, using an LDAP service
>   hosted under the domain name.*

We have standardised our identities on the form that we named
[DoNAI](http://donai.arpa2.net), short for domain-or-NAI, where NAI is a
standardised user\@domain format.  The advantage of this format is that we can
always derive the domain responsible for the identity, and inquire about it.

OpenPGP has an [well-defined
mechanism](http://rickywiki.vanrein.org/doku.php?id=globaldir-5-openpgp) for
hosting OpenPGP key servers under one’s domain, and this allows any domain owner
to affirm locally used identities *without a need for a key exchange party*.

More in general, the idea of a [Global
Directory](http://rickywiki.vanrein.org/doku.php?id=globaldir-1-concepts) is a
generally usable LDAP server that publishes information about a domain, in a
well-standardised format that can be queried by automatic processes.  LDAP is
also highly efficient; put those together and it is an excellent information
source for the TLS Pool.  For example, to validate an X.509 Certificate.

Finding information in the Global Directory is not difficult; for example
`john.doe@example.com` is looked up in the LDAP server for `example.com`.  This
might host multiple domains, so the base from which searching starts is
`dc=example,dc=com` and searches underneath can be made for things like
`(uid=john.doe)` and, where applicable, some structural information such as
supported object classes and/or attribute types.

Why use LDAP, when DNS can also hold a lot of information?  Mostly for reasons
of privacy.  Where names of hosts and domains are commonly considered public,
the same may not hold for user names under a domain.  Not in a spam-ridden world
at least.  DNS cannot be stopped from publishing all information and even modern
protection measures such as NSEC3 cannot stop determined parties from iterating
over its contents.  LDAP on the other hand, handles each query in its server.
This means that it [may be setup to refuse to deliver
listings](http://rickywiki.vanrein.org/doku.php?id=globaldir-2-publication) and
for example return information about user `john.doe` only when his `uid` is
mentioned explicitly in the query.

Another reason for preferring LDAP for user information is that it is not common
(in a large company) for DNS to be under the same control, and permit the same
level of flexibility, as a database behind the public LDAP service.
