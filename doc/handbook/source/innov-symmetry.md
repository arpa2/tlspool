Symmetry for Peer-to-Peer Networks
==================================

>   *TLS is an asymmetric protocol, with a clearly defined client and server.
>   Even if this serves many of today’s applications, it leaves peer-to-peer
>   networks, whose agents are more symmetric, at a total loss.  A simple
>   innovation of the TLS system can however incorporate better symmetry in the
>   protocol, and thereby provide proper TLS support for those peer-to-peer
>   networks.*

The normal TLS Handshake starts with a message from each end, one is a `Client
Hello` and the other a `Server Hello`.  This is the start of an asymmetric
exchange.

Thinking symmetrically however, is not so difficult.  In the end, what we would
care about is whether the remote peer has an authenticated identity, and whether
we are willing to provide local credentials (and which) to authenticate.  The
details of the mechanisms and cryptography are, given a suitable security level,
arbitrary choices — and the same applies to the client or server roles for many
applications.

TLS however, has been designed with strict client-server applications in mind,
and so nobody cared about this.  The rising demand for peer-to-peer networks, as
a result of tapping and profiling on “central” servers, puts up a different
use-case: one where the sides use symmetric protocols, and may not easily
distinguish between client and server side.  Moreover, transport protocols such
as TCP, UDP and SCTP can be setup symmetrically.

The [symmetric variation of
TLS](https://datatracker.ietf.org/doc/draft-vanrein-tls-symmetry/) is a simple
modification that permits sending a `Client Hello` from both ends when an
asymmetric exchange is desired.  The two sides will determine which of the sides
“wins” the client role and which “wins” the server role, and continue as with
asymmetric TLS — in the knowledge that the main issues involved are about the
remote and local credentials and trust in them, rather than the role played in
the TLS handshake.

The TLS Pool is supportive of this scheme, in the sense that it permits
role-neutral use of TLS.  **TODO:** The underlying TLS library is not yet up to
pace, and so the TLS Pool is not a complete implementation of Symmetric TLS at
this time.
