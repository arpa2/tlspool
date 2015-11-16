TLS Pool and Anoymising Precursors
==================================

>   *The “Anonymising Precursor” is a new idea introduced by the TLS Pool.  It
>   works just as the rest though, encapsulating the knowledge into the pool and
>   making decisions on rather straightforward information (namely, service
>   name and the role that is being played).*

What is an Anonymising Precursor?
---------------------------------

While setting up a TLS connection, a lot of information is exchanged without
encryption.  This includes credentials such as certificates, containing not only
names but also public keys (which are excellent long-term identifiers) for their
owners.  An anonymising precursor is a phase preceding the "normal"
TLS handshake to setup a layer of encryption without authentication.

Once established, secure renegotiation can be initiated to authenticate parties
as would "normally" be expected, and return the TLS connection with the same
security, but without having revealed all the identifying information needed
for the "normal" TLS handshake.

What does this add to TLS security?
-----------------------------------

The first phase is an ANON-ECDH exchange.  This is known to be open to
man-in-the-middle attacks, so a third party might be sitting in between the end
points that setup the TLS connection.  The properties of secure renegiation
however, ensure that such a situation will be detected in retrospect.  This
means that an attacker will be noticed, and that no silent observation of
identifying information is possible.

Why is this not usable for all protocols?
-----------------------------------------

The TLS Pool will always followup on an ANON-ECDH phase with whatever
authenticating cipher suite it deems necessary, but the remote party may
use another implementation, and return control to the application after
the ANON-ECDH handshake alone; it would still support renegotiation though.

As soon as the application gains control, information may be passed around
that shows up as TLS-protected, but is in fact not authenticated.  This happens
in the above situation on remote party that happily accepts ANON-ECDH, but it
depends on the application protocol whether this leads to security problems.

Consider SMTP; the server sends a banner to welcome and greet the recipient,
but without formal meaning (except an "OK" code).  If this got modified by an
intermediate it could not do harm.  After the banner, the local party must act,
and if it requires authentication before sending anything, as is the case with
the TLS Pool, then nothing harmful can happen.  As a result, SMTP is completely
safe to initiate within unauthenticated ANON-ECDH.

Reasoning similar to SMTP applies to POP3.

IMAP is more interesting; it can still use ANON-ECDH, but requires some more
care and attention and it does show that not everything can be automatically
secured with an ANON-ECDH precursor.  IMAP servers also send a banner to
welcome the client, but this time it includes a list of
features supported on the server, and an intermediary could modify this
information to establish a service degredation.  Usually however, it is not
considered a privacy violation if this information is shown to this
intermediary.  This means that we can permit ANON-ECDH, provided that either
(1) the banner is not sent before the second handshake is complete, or
(2) the TLS stack detects intermediate changes after the handshake is complete,
which requires the common RFC 7627 "extended master secret" and RFC 5746
"secure renegotiation" extensions.

For IMAP, the reasonable thing to do is to let the server refuse ANON-ECDH
if it does not provide these facilities, or when the client does not offer
them in its Client Hello.  Alternatively, the server may offer ANON-ECDH in
either case, but always hold back on sending the banner before the second,
authenticated handshake
has completed (which is what the TLS Pool will do).  The server thereby
protects the information that it sends.  The client should validate that
both extensions are being used by the server *if* it received any data
before the second handshake is complete.

What this demonstrates, is that protocol-specific knowledge is needed to
decide whether and how to handle Anonymous Precursors.  The TLS Pool is provided
with a service name so it is able to decide on that.  This extends the view
that technical detail is ideally integrated into the TLS Pool to relieve the
application from such complications -- and the involved potential of being
subjected to security attacks.

Another interesting protocol is HTTP.  As soon as the client has connected
to a server over TLS, it will send a request, revealing potentially private
information that also needs to be authenticated, so it needs better protection
than the IMAP banner which only needed authentication in hindsight.
This means that the reasoning from IMAP cannot be applied.  Still, as it
turns out, HTTP can in practice make good use of ANON-ECDH.

For an HTTP client, the reasoning is quite simple; it should not offer ANON-ECDH
unless it is going to complete the second handshake before sending the HTTP
request.  This can easily be enforced in the client code; the TLS Pool
handles the Anonymous Precursor in the same command as the customary
continuation into server authentication, so the potentially-sensitive
HTTP request is only sent to an authenticated server.

The HTTP server is another matter; it may assume that the client handles
its own privacy well enough by implementing the foregoing mechanism.  However
when the server requires authentication, it should ensure the authenticity
of any request data sent before the second handshake is complete.  It could
reason as for IMAP, leaving the privacy matter to the client, but that would
mean that extended master secrets are required for a protocol that is not
known for its willingness to mature towards new developments; HTTP is part
of many code bases and not all of them are easy to update.  So in the specific
case of HTTP, we lean towards not supporting it on the server when the
client identity is required.

Note however, that any TLS endpoint that does not desire an authenticated
identity for its remote peer can accept ANON-DH without risk.  This happens to
be true for the majority of HTTP servers; even when client identity is
requested or required, a common HTTP server would start without asking for
it and then, based on the path that the client sends in a request, renegotiate
TLS to ask for the client ID.  Since ANON-DH only precedes the first
handshake, it will be common to find HTTP servers that can permit ANON-DH
prefixes for this general reason.


Registry for Protocols
----------------------

By default, the TLS Pool will not offer to the ANON-ECDH precursor handshake.
Only when the service specified during the STARTTLS setup is known to work,
it may start in this vain.  And even then, it will distinguish the choice
between client and server roles; and it will correctly handle connections that
may be either.

Flags that may influence this decision are those that indicate that the remote
identity is ignored by the application; if this is the case, then
unauthenticated traffic from the remote does not matter either.  Note that the
identity of clients is unknown in many TLS connections; the most common use
cases call for an authenticated server and an unauthenticated client, to provide
for situations with any clients coming from anywhere.

The code for the TLS Pool contains a registry for service, leading to their
support for client and/or server roles.  This registry is openly discussed on
the mailing list, found on <http://lists.arpa2.org/mailman/listinfo/tls-pool> —
please go there to propose changes to the list, and be open for a discussion
before the change is accepted.  Although security is an overriding concern,
the general intention is to arrive at consensus before things are changed
in the registry built into the TLS Pool.

One invalid service name (according to RFC 6335) has been created through the
use of an underscore.  This name can be used to explicitly
permit an Anonymous Precursor to a generic protocol.  The name is
`generic_anonpre`.  Use this as a service name for generic protocols that
have no formally registered service name but that do permit the
Anonymous Precursor phase.

Implementation status
---------------------

The current implementation holds the code for the anonymising precursor,
but the registry for supported applications is empty.  The reason is that
the underlying GnuTLS library does not seem to implement it as we had
expected,
[read this](http://lists.gnutls.org/pipermail/gnutls-help/2015-November/003998.html)
for details.  As soon as this is resolved, the anonymising Precursor
will be enabled, and automatically applied.  The most probable cause is
with GnuTLS however, so there is an external dependency to make this
possible.

