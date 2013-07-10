------------------------
TLS POOL SOCKET PROTOCOL
------------------------

The TLS pool concentrates interactions about TLS, and does this by offering
service on a UNIX domain socket.  An application using the TLS pool would
open a connection to this socket by specifying its file name.

Once connected, the TLS pool awaits command requests.  These are always sent
on the initiative of the application, and each command results in exactly
one response, at least as long as the connection remains open.  This means
that the TLS pool will never initiate concurrent interactions, but the
application is free to do so.  Packets include an identifier that are
faithfully copied from request to response.

Some commands may take some time to finish, which is why concurrency is
supported.  But slower batch processes, which usually are mere scripts,
have the freedom of not adopting the corresponding complexity.



Commands and responses
======================

Every command sent to the TLS pool is dignified with precisely one response.
This response is either a notification of ERROR or SUCCESS, but depending
on the commmand sent it may also take another shape.  For example, the PING
command returns the same PING message format that it received, filled with
different data.

Error responses contain a textual message and a code which is taken from
<errno.h> so there are no new number series to represent error codes.
The textual message is meant to supply useful feedback to a user or
operator.  This message is usually easier to handle than the errno
value.


Support for STARTTLS and TLS-only
=================================

Older protocols used to define a separate protocol name nad port for
TLS-wrapped versions of their work.  The modern approach is to first
negotiate features, and if supported to initiate TLS over the existing
TCP connection with STARTTLS.

Both these approaches are supported through the TLS pool.  Client and
server generally know when they need to start TLS; either right at the
beginning of a TCP connection, or after an acknowledged STARTTLS
request.  The idea is then that both sides initiate TLS in tandem,
possibly by talking to their local TLS pool.


Initiating the socket connection
================================

After the application has connected to the TLS pool, it is a good idea
to send a PING command.  This command ships the application's identity
to the TLS pool, and the response carries the identity of the TLS pool.
The TLS pool normally logs this data, and the application might do the
same.

Identities take a simple string format.  They start with a date in the
well-known YYYYMMDD format, followed by a domain-bound identity which
is either a domain name or has the form user@domain for something like
a domain name.  The date anchors a semantics version and the
domain-bound identity represents the producer of the implementation at
that time.  The idea is that differences between versions are made
visible, although equivalence cannot be derived.  This may be used
to check if local extensions are supported.

The identity of the TLS daemon is tlspool@openfortress.nl and the
semantics version V1 is datestamped 20130710.  This is stored in
the include file as TLSPOOL_IDENTITY_V1.


Starting TLS as a client
========================

A client can send the STARTTLS_CLIENT command by filling in a number
of fields in the command packet.  In addition, it sends a file descriptor
to TLS-ify as auxiliary data.  This file descriptor is duplicated into
the TLS pool, and further used for the TLS exchanges.

This file descriptor that is duplicated to the TLS pool should normally
be closed as soon as the response comes back, as it is no longer usable.
This is even the case for ERROR responses, as it may be unclear what has
been sent over the wire.  Note however, that exceptions may exist for
SCTP, depending on the protocol used; with SCTP, it could be possible to
send encrypted streams over one file descriptor, and unencrypted streams
over the original file descriptor.

The client must indicate whether the file descriptor runs IPPROTO_TCP,
IPPROTO_UDP or IPPROTO_SCTP.  If it wants to negotiate DTLS instead
of TLS, it should raise the corresponding flag; this is impossible
for TCP, required for UDP and advisable for SCTP.  In the case of
SCTP, a stream identifier over which to negotiate (D)TLS must also
be supplied.

Several flags have been defined to loosen or tighten the validations
made by the TLS pool, or possibly passed over to external components.
The default setting of 0 means that identities are verified, and that
DNS is mistrusted unless the DNS authoritative has not implemented
DNSSEC.  User identities retrieved from LDAP are requested over an
unvalidated connection under the assumption that TCP is hard to
tackle and that the remote host has been identified as solidly as
permitted based on DNS information.

The TLS pool uses a cache for authentications and authorizations that
have worked well.  These caches may be bypassed for situations where
a step in a process requires explicit validation, for instance at a
time of contractual agreement such as a payment or order acknolwedgement.
There are flags to indicate that the caches should be ignored.

Finally, there are local and remote identities exchanged during the
process.  Each takes the shape of either a domain name or a
user@domain format.  Unknown identities can be represented with an
empty string, so with a NUL character in the first position of a
C-string.

Usually, a client is aware of the remote identity being addressed,
and would set this value.  This would make it possible to validate
that remote identity as it is presented.  Furthermore, it makes it
possible to send Server Name Indications, which are a trick to help
old-fashioned TLS protocols like HTTPS to support domain-based
virtual hosting.

If the remote identity is not set, then the validated remote identity
that is exchanged over TLS will simply be reported back as part of the
command acknowledgement, which uses the same packet format.  It is taken
for granted that a client that does not specify its remote identity will
accept anything.

Similarly, the client should set a local identity to use over the
connection if it has ideas about that.  If it does not, the TLS pool
may find multiple to choose from, and present these for approval,
one at a time.  This interaction is not optimal and should be avoided
if possible.  The main reason it exists is to permit the TLS pool
to bypass client authentication if the remote indicates that this is
acceptable.  When client authentication is requested or required by
the remote peer, which is true by default if it is a TLS pool without
overriding commands, then it makes more sense to indicate what local
identity to supply to the remote.

The probes that propose a local identity to use are sent in response
to the STARTTLS_CLIENT command, which is continued after acceptance.
If a local identity is not accepted, it should be set to the empty
string and the command returned to the TLS pool with the same request
identity.

The final response to the STARTTLS_CLIENT command request is either an
ERROR or a STARTTLS_CLIENT command response.  The latter contains the
validated results of the succeeded TLS connection setup, including
any local and remote identity that have been established.  In addition
to the response packet, this positive command response includes a
file descriptor which can be used for TLS-wrapped traffic.  The ERROR
condition is raised when default or flagged requirements have not
been met by the connection setup.


Starting TLS as a server
========================

A server can send a STARTTLS_SERVER command to the TLS pool to
initiate TLS over a connection.  To do this, it fills out a number
of fields in the command packet.  In addition, it sends a file descriptor
to TLS-ify as auxiliary data.  This file descriptor is duplicated into
the TLS pool, and further used for the TLS exchanges.

This file descriptor that is duplicated to the TLS pool should normally
be closed as soon as the response comes back, as it is no longer usable.
This is even the case for ERROR responses, as it may be unclear what has
been sent over the wire.  Note however, that exceptions may exist for
SCTP, depending on the protocol used; with SCTP, it could be possible to
send encrypted streams over one file descriptor, and unencrypted streams
over the original file descriptor.

The server must indicate whether the file descriptor runs IPPROTO_TCP,
IPPROTO_UDP or IPPROTO_SCTP.  If it wants to negotiate DTLS instead
of TLS, it should raise the corresponding flag; this is impossible
for TCP, required for UDP and advisable for SCTP.  In the case of
SCTP, a stream identifier over which to negotiate (D)TLS must also
be supplied.

Several flags have been defined to loosen or tighten the validations
made by the TLS pool, and they are described above for the client.

As a rule, servers do not know the remote identity that they are
communicating with.  There may be exceptions, where a protocol did
exchange this information prior to a STARTTLS exchange, but these
are exceptions.  So usually, a server will not setup a remote identity
in its STARTTLS_SERVER request command.  If it is set, then the
TLS client must match the identity, on top of its validation.

A server may have one or more alternate identities.  If it has one,
it can set it up as its local identity.  If it has multiple, then
the remote peer may have to supply one through a Server Name
Indication.  If the TLS pool derives a remote identity, it will
propose it to the server through a STARTTLS_LOCALID command response.
This package contains a remote identity to approve.  It may be
accepted as is, modified, or disapproved of by setting it to the
empty string.  The STARTTLS_LOCALID packet should then be issued
as a command to the TLS pool, while retaining the request identity.
When rejecting a proposed local identity, the TLS pool may issue
more proposals in independent command responses.

Note that identities are not always exchanged.  If both sides of a
TLS connection support anonymous TLS connections, then there may
be no need to exchange certificates at all.  Such anonymous connections
are not common, but they are certainly possible.

The final response to the STARTTLS_SERVER command request is either an
ERROR or a STARTTLS_SERVER command response.  The latter contains the
validated results of the succeeded TLS connection setup, including
any local and remote identity that have been established.  In addition
to the response packet, this positive command response includes a
file descriptor which can be used for TLS-wrapped traffic.  The ERROR
condition is raised when default or flagged requirements have not
been met by the connection setup.


Token PIN entry
===============

The use of tokens stored on PKCS #11 implies that tokens are accessed,
for which PIN codes must be entered.  These may be setup in the
configuration file, but this is not always an acceptable practice for
security reasons.

Although applications that issues STARTTLS commands could double as
PIN entering applications, this is not generally the advised approach.
It is desirable to move credentials away from programs that engage in
online activities, and if the TLS pool cannot contain the PIN, it
should facilitate entry of PINs by independent programs.

To this end, a program can access the TLS pool socket and issue a
PIN_ENTRY_OFFER command request.  In response to this command, the
TLS pool can issue a PIN_ENTRY_OFFER command response, asking for
a particular PIN code.  The user is somehow asked to enter the
said PIN, and another PIN_ENTRY_OFFER is submitted, this time
carrying the PIN.  All these interactions carry the same request
identity.

The different formats of PIN_ENTRY_OFFER are distinguished by
looking at the PIN string.  If it is an empty string, it is not
submitting a PIN and it is merely an offer to pickup on future
PIN validation proposals.  The empty PIN can also be supplied to
refuse entering a PIN; interestingly, the user is usually able
to do this too, and it is often the response to hitting a
cancellation button that scripts may or may not take note of.

If a PIN entry service is to be stopped, the program usually
disconnects from the TLS pool.  Alternatively, it is possible
to respond to a PIN_ENTRY_OFFER from the TLS pool to the PIN
entry application by sending an ERROR with the same request
identity, and expecting to see a SUCCESS response to that.

TODO:The TLS pool can manage either exactly one PIN entry program,
or multiple which are then tried sequentially, with a timeout.
Most PIN entry programs would not set the flag that enables
multiple PIN entry programs at the same time.

