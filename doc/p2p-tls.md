Peer-to-Peer TLS
================

>   *The TLS Pool is prepared for support for peer-to-peer TLS.  This is a new
>   idea, so it needs some guidance.*

Many network protocols know which side acts as a server and which as a client,
in terms of setting up the connection.  TLS needs this information.  There are
however protocols that have no such direct separation of roles; symmetric
protocols such as MSRP or generally peer-to-peer protocols work perfectly fine
without appointing a party as the client, and the other as a server.  The fact
that TLS needs to know this information is not helpful in such circumstances.

One might argue that TCP connections are client-server connections, but this
would overlook two facts.  UDP connections are not necessarily client-server
connections and in fact TCP has always supported two active sides getting
together.  This principle is embedded in NAT routers, which are founded on the
TCP state diagrams.  Finally, SCTP has also been designed to permit two active
sides contacting each other at the same time.  Clearly, the stringent
appointment of client and server roles is only a strict necessity for the TLS
stack.  Peer-to-peer TLS resolves this matter.

What does peer-to-peer TLS do?
------------------------------

The active participant in a TLS connection starts off by sending a ClientHello
record.  This is normally answered by a ServerHello.  In case of peer-to-peer
TLS connection, an additional form is allowed, namely one where both sides send
a ClientHello, and one of these is discarded as if it was never sent.  The
discarding recipient then responds with a ServerHello.

The tie-breaker that helps to decide which party should continue in the role of
a client and which should continue as a server is an extension that is included
in the ClientHello.  This extension from each side introduces a random number of
sufficient size to make it practically impossible to generate the same random
number on both ends.  The sender of the lower value ends up as the client, and
the sender of the higher value ends up as the server.  The case where random
number is the same on both sides is considered a refusal of the attempted TLS
setup and leads to connection breakdown.  The random numbers have a fixed
minimum and maximum value; these values are used when a ClientHello wants to
indicate that it only wants to be a client, or that it only wants to be a
server.

How does this impact flags during STARTTLS?
-------------------------------------------

When invoking the STARTTLS command on a TLS Pool, the possible roles for the
local and remote end must be setup; each may be flagged suitable as a client
and/or a server.  A protocol that is strictly client-server will set only the
client role on one end and only the server role on the other end; a protocol
that is symmetric would send both roles on both end points.

Where traditional TLS stack design requires server flags in server certificates,
this is turned into a policy option under the TLS Pool.  The application does
not require such properties from the TLS Pool.

One thing that is truly important however, is whether the remote identity was
authenticated, and whether or not a local identity may be shared.  This
information is mirrorred, and is therefore suitable for the more flexible setup
of a p2p TLS protocol.  The requirements to this end are setup in flags during
STARTTLS; this is done in terms of local and remote properties, rather than in
terms of what the client and server responsibilities are.  In the end, it does
not matter if the remote authenticates with a client certificate or with a
server certificate, as long as it proves its identity to be authentic, is the
idea.

Details of implementation with GnuTLS
-------------------------------------

GnuTLS needs to be setup differently depending on whether it will be acting
as a client, or as a server.  Think of such things as the priority string
and the credentials.  The general structure uses a callback function for
the reception of a ClientHello:

	clienthello () {
		...
		...setup GnuTLS session as a server...
		...
	}

	starttls () {
		...
		if (tlsmodes & CLIENT) {
			...setup GnuTLS session as a client...
		}
		if (tlsmodes & SERVER) {
			gnutls_handshake_set_post_client_hello_function (
				session,
				clienthello);
		}
		...
		...perform the handshake...
		...
	}

The reasoning is that the client setup should be available when it is
*possible* that the TLS session will act as a client, and that there is
time enough to overwrite this with server settings when a ClientHello is
received.  Indeed, while in `clienthello()`, the soon-to-be server has
not yet sent out anything and it is only at this point that it will
always require the server setup to be established.  The clearance of
previously made client settings is not a waste; it was actually needed
if the session was willing to be a client (and only then).

