Support for OpenPGP Keys
========================

>   *Anyone involved with cryptography knows it: X.509 is what is sold for
>   infrastructure, but OpenPGP is the system that is actually being used across
>   the world.  Work has been done to support the use of OpenPGP keys in TLS,
>   but it is not widely developed.  As part of TLS Pool innovations, it is
>   generously supported.*

**TODO:** At present, OpenPGP keys can be exchanged, but they are not fully
implemented in [validation
expressions](https://github.com/arpa2/tlspool/blob/master/doc/validation.md).

The TLS Pool is made with the explicit intention of having as many alternative
possibilities lined up, to have something to select from in policies and
security settings.  OpenPGP public keys have been a possible certificate type in
TLS for quite a while, but it is not commonly implemented.

The most probably reason for this is the effort it takes to make the X.509
setup, which is hardly motivating to do it again.  Given our view on “having a
way out” this is not really helpful.  We aim for a future where identities are
managed and rolled automatically using something like our
[IdentityHub](http://internetwide.org/blog/2016/06/24/iwo-phases.html), also
because that enables the rollout of such parallel options.  With this in mind,
OpenPGP is already supported in the TLS Pool.
