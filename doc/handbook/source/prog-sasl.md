Working with Authorisation
==========================

>   *The TLS Pool reveals “only” authenticated identies to applications.  This
>   is a perfect fit for authorisation.  An excellent place for this would be
>   when a TLS-wrapped protocol engages in (embedded) authentication, such as
>   SASL.*

Please be careful to note the following concepts, which are distinct:

-   *authentication* is concerned with proof of identity;

-   *authorisation* is concerned with assigning rights to perform certain
    actions.

The two are often twined, because authorisation decisions tend to be based on
authenticated identities.  For example, they might follow an [Access Control
List](http://donai.arpa2.net/acl.html) written down in terms of identities which
are assumed valid.

When using the TLS Pool, the best place for authentication is during the TLS
handshake.  The TLS Pool can then deliver local and remote identities that have
been used in the handshake; and it will deliver an error if the handshake
failed, so a handshake result always includes authenticated identities only.
There may be an empty string for either though — to indicate that the identity
was absent or unsupported.

Many applications may be helped with literal matches of the authenticated
identity to a local variable, or database entry.  Or they may use it as a
starting point for looking up information to be used in dynamic service output
(such as a web page that is rendered live).  More complex applications may need
an ACL, and even more complex ones will resort to a centralised authorisation
service, such as RADIUS or Diameter.

The latter is precisely the general model that we are aiming for when we
introduce [separate
hosting](http://internetwide.org/blog/2014/11/19/back-to-hosting.html) for
identities and for services.  The reason to enjoy a central authorisation
service is that it is supportive of caching and clever, privacy-supportive
tricks to withhold as much information from parties as possible.

Back to the protocol at hand though.  Authorisation is useful but when to use
it?  A client has authenticated and now needs to make an attempt to use a
particular identity.  That does not have to be the authenticated identity; it
may well be a [pseudonym, alias, role, group
name](http://internetwide.org/blog/2015/04/23/id-3-idforms.html).

Many protocols will request a login from the user, even when they are running
inside a TLS connection.  This wrapped login may indeed be used to obtain a
username (and perhaps a password that could be ignored) that can be treated as
the desired name — and then authorisation can be employed to verify whether this
is possible under the authenticated identity found in TLS.

An authentication method that is directly supportive of this style (without even
a need to ignore a password) is the [SASL
EXTERNAL](https://tools.ietf.org/html/rfc4422#appendix-A) mechanism.
Conceptually, the SASL EXTERNAL user specifies an identity that it desires, and
by referring to this specific mechanism it tells the server to “go look around”
for context that assures this fact.  In most cases, this will relate back to the
TLS wrapper for the connection.

Not all implementations of SASL EXTERNAL are as general as the idea behind it
though.  The rather common scenario of using X.509 Certificates for
authentication may have been hard-coded in servers.  There is no reason other
than pragmatics for such choices; a `mod_ssl` delivers a complete certificate,
and so a parser for X.509 is built into the SASL EXTERNAL implementation.  When
using a TLS Pool however, a fairly straightforward comparison with the
authenticated identity is available.  Or, if the more general ideal of
authorisation is to be supported, then the step through RADIUS or Diameter may
be taken.
