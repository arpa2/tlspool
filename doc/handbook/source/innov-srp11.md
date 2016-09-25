Best-effort Passwords through SRP \#11
======================================

>   *Passwords are a nuisance of using online services.  Or at least, that is
>   what we are made to believe.  Instead of fixing the crippled uses of
>   passwords with wallets and generators, we should move to better
>   cryptography.  SRP is an excellent stepping stone, but with our novel
>   innovation through SRP \#11 it really becomes exciting.*

Passwords are a nuisance, not just to end users but certainly also to
cryptographers.  The reason is, they are always the same so once tapped it can
be used by others as well.  Compare that to schemes based on keys, which do not
share their private keys, but instead perform a task that provably can only be
completed by the holder of the private keys.

Sometimes, there is a middle ground.  Secure Remote Passwords are such a middle
ground; they have pleasant cryptographic properties and, given that we still
want to let users type in passwords, then SRP is a good solution.  And indeed,
[SRP is integrated into TLS](https://tools.ietf.org/html/rfc5054) by RFC5054.
There are a few things that remain to be desired however.

The SRP scheme is founded on Diffie-Hellman, and shares its keys of sizes that
are increasingly felt as unpractically long.  An elliptic-curve variation would
be quite good to have standardised.

The second concern is that SRP still relies on passwords and, through that, on a
limited amount of entropy (“surprise”) and so, that it may still fall for things
like dictionary attacks.  In a TLS Pool world, the ideal would be to rely on a
secret stored in PKCS \#11 so we can integrate it with the rest of the
cryptographic algorithms, and at the same high level of achievable security.

We have indeed worked on a variation that we call [SRP
\#11](https://github.com/arpa2/srp-pkcs11/blob/rfc5054_compat/doc/design/srp-pkcs11.pdf)
— a method that makes *no changes on the server side* and yet, through
innovative changes in the computation on the client end, can be made to depend
on access to a PKCS \#11 device.  Such enforced dependency is referred to as
*two-factor authentication*, where you need to know something (the PIN) and hold
something (the PKCS \#11 device) — the norm throughout our design of the TLS
Pool cryptography.

Back to the first concern, that of a lacking elliptic curve variant.  We believe
our work on SRP \#11 to be important precisely because it can help as a
selection criterium for an Elliptic Curve SRP replacement, and its integration
into the TLS standard.
