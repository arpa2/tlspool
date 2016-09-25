# Security Innovation

>   *The TLS Pool is designed to support innovation in the TLS protocol,
>   and its security in general and even
>   its cryptographic protocols specifically.
>   Let us explain how this relates specifically to the TLS Pool design,
>   and how it may impact the future of Internet stability and maturity.*

The TLS Pool centralises control over TLS.  That makes it a very easy place
to conduct innovation, in a way that applies to many uses at the same
time.  And by incorporating alternatives for SSH and GSS-API in future
releases, this can only improve.

Being a pretty central station, it is possible to invest the efforts of
launching new protocol variations in this one place, and let many applications
profit from it at once.  Existing TLS stacks are built as libraries (so not
as background programs) and still require the application loading them to
actually use the new protocol variations.  The TLS Pool makes a bold decision
to be independent from application programmer logic, and instead be driven
by security programmer logic, making it much easier to innovate from a
cryptographic or protocol perspective.

A few examples of this follow in the subsections underneath this one.
It is useful to understand that professional environments want to raise
a minimum bar for their security protocol usage, and the diversity of
support for the TLS stack by different applications makes it difficult
to raise that bar too high.  In a future where perhaps all software uses
the TLS Pool, it is possible to set a much higher standard as the minimum
norm for connection security.  This translates directly in the level of
attacks that can be avoided, in the simplicity of managing the network
and in the straightforwardness to manage security.

Note that it is not a coincidence that this project integrates with the
[SteamWorks](http://steamworks.arpa2.net)
project for subscriptions to central configuration.  A corporal security
policy may be changed and then virtually-immediately picked up by any
and all implementations following it.

Though this may reak of grandure, this is far from the truth; the TLS Pool
prides itself on using open specifications for all its APIs, and being
open to alternative implementations.  In a secure world, nothing beats
the capability of a user to simply replace the software that she relies
on without noticing any functional variation!

Let us address a few specific innovations that the TLS Pool either introduces
or enables:

  * [Separation from Applications](innov-daemon.html)
  * [Reliance on PKCS #11](innov-pkcs11.html)
  * [Backend to SteamWorks](innov-steamworks.html)
  * [Support for OpenPGP Keys](innov-pgp.html)
  * [Kerberos through TLS-KDH](innov-tlskdh.html)
  * [Best-effort Passwords through SRP \#11](innov-srp11.html)
  * [Symmetry for Peer-to-Peer Networks](innov-symmetry.html)
  * [Validation Expressions](innov-valexp.html)
  * [Global Directory support](innov-globaldir.html)
  * [Switching Protocols](innov-protos.html)

