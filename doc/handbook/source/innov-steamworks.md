Backend to SteamWorks
=====================

>   *The SteamWorks system is a method of using LDAP for spreading configuration
>   information.  The TLS Pool can put this to good use for setting up its
>   dynamicity-supporting databases.  A backend to SteamWorks is integrated with
>   the TLS Pool to simplify the attachment to this system, and thereby to
>   enable provisioned control over that pesky thing called security.*

The subdirectory
[pulleyback](https://github.com/arpa2/tlspool/tree/master/pulleyback) in the TLS
Pool distribution builds a dynamic library, `pulleyback_tlspool.so` (or `.dll`
on Windows) that can be loaded into the
[Pulley](http://steamworks.arpa2.net/pulley.html) component of
[SteamWorks](http://steamworks.arpa2.net).  The purpose of this library is to
store information in the TLS Pool databases `localid.db`, `disclose.db` and
`trust.db` when things change in subscribed LDAP sources.

We have created an [LDAP schema
extension](https://github.com/arpa2/tlspool/blob/master/doc/steamworks-ldap-scheme.md)
that may be used to represent TLS Pool configurations in LDAP.  This is intended
to offer possibilities, but it is certainly not the only possible representation
of data from which SteamWorks can configure the TLS Pool.  If your system
already has an LDAP structure that represents users, credentials and trust, then
you can use that too.

The basic idea of SteamWorks and specifically of the [PulleyScript
language](http://steamworks.arpa2.net/intuition.html) is that it can pick and
choose from LDAP, and combine things found.  As a matter of fact, Pulley
surpasses the expressive power of LDAP queries by supporting relations and
constraints to be applied between different objects; this makes LDAP as powerful
to query as SQL — except that LDAP is a protocol standard, and can apply to any
source that is LDAP-compliant.
