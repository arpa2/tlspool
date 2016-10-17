------------------------
TLS POOL SOCKET PROTOCOL
------------------------

    **NOTE:** The socket protocol is
    `under evaluation`_
    and may be substituted by a DER-based alternative.  Please use the wrapper
    library `libtslpool` until the final decision has been made.

.. _`under evaluation` : https://github.com/arpa2/tlspool/issues/42

The TLS Pool concentrates interactions about TLS, and does this by offering
service on a UNIX domain socket.  An application using the TLS Pool would
open a connection to this socket by specifying its file name.  The same
access control primitives as for files socket can be configured for this
socket -- user, group and chmod access settings.

Once connected, the TLS Pool awaits command requests.  These are always sent
on the initiative of the application, and each command results in exactly
one response, at least as long as the connection remains open.  This means
that the TLS Pool will never initiate concurrent interactions, but the
application is free to do so.

Some commands may take some time to finish, which is why concurrency is
supported.  Packets are sent to the TLS Pool with an identifier that will
be copied from the request to the response.  But slower batch processes,
which usually are mere scripts, have the freedom of not employing the
complexity corresponding to concurrent control.  The TLS Pool happily serves
a multitude of simultaneous client connections, so a single slow client will
not slow down the other TLS Pool clients.

Some requests to the TLS Pool return a response that invites a new request
with additional data; the best example is the PINENTRY command which returns
to request a PIN being entered.  In such followup-requests, the callback
identifier from the response should be copied into the new request.

The most likely structure for the coupling of messages based on request
or callback identities is by looking up entries in a table.  For reasons
of security, it is important to verify that the right socket is
sending the desired response.


Design Angle
============

The design angle of the TLS Pool is to take the responsibility of
handling security-specific knowledge away from applications.  This has
security benefits, among which that it simplifies the code in an
application; the application designer delegates the security of a connection
to the TLS Pool and only talks to it in terms of identities for a local and
remote node.


Commands and Responses
======================

Every command sent to the TLS Pool is dignified with precisely one response.
This response is either a notification of ERROR or SUCCESS, but depending
on the commmand sent it may also take another shape.  For example, the PING
command returns the same PING message format that it received, filled with
different data than for an ERROR or SUCCESS response.

Error responses contain a textual message and a code which is taken from
<errno.h> so there are no new number series to represent error codes.
The textual message is meant to supply useful feedback to a user or
operator.  This message is usually easier to handle than the errno
value.

When errors are reported, it may be helpful to look into the log as well.
This may contain much more detail, including things that are too sensitive
to report back to the application.  Note that an application often runs
with end-user privileges, whereas logfiles may be protected for viewing
by the administrator only.


Support for STARTTLS and TLS-only
=================================

Older uses of TLS would define a separate protocol name and port for
TLS-wrapped versions of their work.  The modern approach is to first
negotiate protocol-specific features, and if TLS is supported, to initiate
it over the existing TCP connection with STARTTLS.

Both these approaches are supported through the TLS Pool.  Client and
server generally know when they need to start TLS; either right at the
beginning of a TCP connection, or after an acknowledged STARTTLS
request.  The idea is then that both sides initiate TLS in tandem,
possibly by talking to their local TLS Pool.


Initiating the Socket Connection
================================

After the application has connected to the TLS Pool, it is a good idea
to send a PING command.  This command ships the application's identity
to the TLS Pool, and the response carries the identity of the TLS Pool.
The TLS Pool normally logs this data, and the application might do the
same.

Identities take a simple string format.  They start with a date in the
well-known YYYYMMDD format, followed by a domain-bound identity which
is either a domain name or has the form user@domain for something like
a domain name.  The date anchors a semantics version and the
domain-bound identity represents the producer of the implementation at
that time.  The idea is that differences between versions are made
visible, although equivalence cannot be derived.  This may be used
to check if local extensions are supported.

The identity of the TLS daemon is api@tlspool.arpa2.org and the
semantics version V2 is datestamped 20151111.  This is stored in
the include file as TLSPOOL_IDENTITY_V2.

As part of the PING exchange, a "facilities" bitfield is exchanged.
The provided value indicates what the TLS Pool client might support,
the returned value has reset those facility flags that the TLS Pool
is not willing to support.  Each can use a PIOF_FACILITY_ALL_CURRENT
constant as a default setting for what it will support; in case of
the TLS Pool, configuration settings may remove facilities from general
use.


Starting TLS as a Client
========================

A client can send the STARTTLS command by filling in a number
of fields in the command packet.  As part of this, it requests a local role
as a client, and a remote role as a server.  In addition, it sends a file descriptor
to TLS-ify as ancillary data.  This file descriptor is duplicated into
the TLS Pool, and further used for the TLS exchanges.

This file descriptor that is duplicated to the TLS Pool should normally
be closed as soon as the response comes back, as it is no longer usable.
This is even the case for ERROR responses, as it may be unclear what has
been sent over the wire.  Note however, that exceptions may exist for
SCTP, depending on the protocol used; with SCTP, it could be possible to
send encrypted streams over one file descriptor, and unencrypted streams
over the original file descriptor.

The distinction between the client and server is purely indicated by flags.
For a client, the flags to be set are PIOF_STARTTLS_LOCALROLE_CLIENT
and PIOF_STARTTLS_REMOTEROLE_SERVER.  These flags make it possible to
enable peers that are impartial to their or their remote's role as a client
or server.  This helps with peer-to-peer protocols, symmetric applications
and autometic (re)connect.

Several flags have been defined to loosen or tighten the validations
made by the TLS Pool, or possibly passed over to external components.
The default setting of 0 means that identities are supplied and
validated.

The client must indicate whether the file descriptor runs IPPROTO_TCP,
IPPROTO_UDP or IPPROTO_SCTP.  If it wants to negotiate DTLS instead
of TLS, it should raise the corresponding flag; this is impossible
for TCP, required for UDP and advisable for SCTP.  In the case of
SCTP, a stream identifier over which to negotiate (D)TLS must also
be supplied.
**Note:** The current implementation may not yet support all these
combinations, but at least the API is prepared for them.

As part of the setup, the application software informs the TLS Pool of
the service protocol that is being run; this should use the IANA standard
names, that are customary visible in /etc/services as well.

The TLS Pool may use a cache for authentications and authorizations that
have worked well.  These caches may be bypassed for situations where
a step in a process requires explicit validation, for instance at a
time of contractual agreement such as a payment or order acknolwedgement.
There are flags to indicate that the caches should be ignored.
**Note:** This is not currently implemented, but the flag exists.

When the TLS Pool reaches a state where it wants to have a handle for
the plaintext view of its connection, it will make a callback to the
client, using the PIOC_PLAINTEXT_CONNECT_V2 command code.  This is a
query that falls within the STARTTLS query by the client, and asks
for another file descriptor to be passed as ancillary data.  It is up
to the client whether this is a socket, an open file handle, or perhaps
a link to a UNIX domain socket that is listened to by a local application.
The latter approach is adopted by the tlstunnel tool, which can thereby
delegate all handling of the TLS wrapping to the TLS Pool, without being
a copying intermediate on either the encrypted or plaintext side of the
protocol.

Finally, there are local and remote identities exchanged during the
process.  Each takes the shape of either a DoNAI_, domain name or a
user@domain format, terminated with a NUL character.  Unknown identities
can be represented with an empty string, so with a NUL character in the
first position of a C-string.

.. _DoANI : http://donai.arpa2.net

Usually, a client is aware of the remote identity being addressed,
and would provide this value as part of the STARTTLS request.  This
would make it possible to validate
that remote identity as it is presented.  Furthermore, it makes it
possible to send Server Name Indications, which are a trick to help
old-fashioned TLS protocols like HTTPS to support domain-based
virtual hosting.  To address potential privacy concerns related to
SNI, there is a flag to suppress its sending from the application.

If the remote identity is not set, then the validated remote identity
that is exchanged over TLS will simply be reported back as part of the
command acknowledgement, which uses the same packet format.  It is taken
for granted that a client that does not specify its remote identity will
accept anything.

Similarly, the client may suggest a local identity to use over the
connection if it has ideas about that.  If it does not, the TLS Pool
may find multiple to choose from, and present these for approval,
one at a time.  This interaction is not final, as will be explained
below.  The main reason it exists is to permit the TLS Pool
to bypass client authentication if the remote indicates that this is
acceptable.  When client authentication is requested or required by
the remote server, which is true by default if it is a TLS Pool that
has not been instructed to ignore the client's identity, then it makes
more sense to indicate what local identity to supply to the remote.

The final response to the STARTTLS command request is either an
ERROR or a STARTTLS command response.  The latter contains the
validated results of the succeeded TLS connection setup, including
any local and remote identity that have been established.  In addition
to the response packet, this positive command response includes a
file descriptor which can be used for TLS-wrapped traffic.  The ERROR
condition is raised when default or flagged requirements have not
been met by the connection setup.


Starting TLS as a Server
========================

A server can send a STARTTLS command to the TLS Pool to
initiate TLS over a connection.  To do this, it fills out a number
of fields in the command packet.  As part of this, it requests a local role
as a server, and a remote role as a client.  In addition, it sends a file descriptor
to TLS-ify as ancillary data.  This file descriptor is duplicated into
the TLS Pool, and further used for the TLS exchanges.

This file descriptor that is duplicated to the TLS Pool should normally
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
**Note:** The current implementation may not yet support all these
combinations, but at least the API is prepared for them.

As part of the setup, the application software informs the TLS Pool of
the service protocol that is being run; this should use the IANA standard
names, that are customary visible in /etc/services as well.

Several flags have been defined to loosen or tighten the validations
made by the TLS Pool, and they are described above for the client.

As a rule, servers do not know the remote identity that they are
communicating with.  There may be exceptions, where a protocol did
exchange this information prior to a STARTTLS exchange, but these
are exceptions.  So usually, a server will not setup a remote identity
in its STARTTLS request command.  If it is set, then the
TLS client must match the identity, on top of its validation.

A server may have one or more alternate identities.  If it has one,
it can set it up as its local identity.  If it has multiple, then
the remote peer may have to supply one through a Server Name
Indication.  If the TLS Pool derives a remote identity, it will
propose it to the server through a PIOC_PLAINTEXT_CONNECT_V2 command response.
This package contains a remote identity to approve.  It may be
accepted as is, modified, or disapproved of by setting it to the
empty string.  The PIOC_PLAINTEXT_CONNECT_V2 packet should then be issued
as a command to the TLS Pool, while retaining the callback identity
to turn it into a callback response.
When rejecting a proposed local identity, the TLS Pool may issue
more proposals in independent command responses.

Note that identities are not always exchanged.  If both sides of a
TLS connection support anonymous TLS connections, then there may
be no need to exchange certificates at all.  Such anonymous connections
are not common, but they are certainly possible.  The TLS Pool does
contain facilities to promote the use of anonymous connections, but
usually as a precursor to an authenticated connection; this establishes
the same level of security but without leaking as much information in
plaintext about local and remote identities and credentials.

The final response to the STARTTLS command request is either an
ERROR or a STARTTLS command response.  The latter contains the
validated results of the succeeded TLS connection setup, including
any local and remote identity that have been established.  In addition
to the response packet, this positive command response includes a
file descriptor which can be used for TLS-wrapped traffic.  The ERROR
condition is raised when default or flagged requirements have not
been met by the connection setup.


Detaching and Reattaching Control over Connections
==================================================

The TLS Pool assumes by default that the process that initiated has
full control over the TLS connection that is setup, and it sends a
"control key" to make this possible.  The control key is needed for
such actions as generating a key based on the master key, and more
aspects of connection management may be added later on.  In these
commands, the ctlkey is used to "prove" that the connection is owned.

In fact, there is another layer of protection for controlling a
connection.  Every TLS connection is connected to a client that
connected to the UNIX domain socket of the TLS Pool.  It is however
possible to detach from that connection, and then to reattach from
another process, in which case the control key must be presented.

As long as a TLS connection is attached to a client socket, the
termination of that client's connection to the TLS Pool's UNIX domain
socket will tear down the TLS connection.  This is another reason
for detaching the TLS connection from a socket; to isolate it from
going down of the initiating program.  A tunnel may use this for
instance, to relocate the attachment to an underlying service
program by passing the control key along with the file descriptor
for the connection.


Control over Validation Policies
================================

Since the TLS Pool wants to isolate security-specific knowledge from
applications, a vital digression from customary TLS-supporting applications
will be that there are no validation policies setup in the application
configuration.  This is extremely helpful because applications vary
greatly in their support for TLS facilities, and this often bogs down the
usefulness of TLS to a least common denominator.

Policy-based control is exercised over a separate interface, which has
its own command language.  The settings are stored in a policy database.
**Note:** At present, no validation has been built into the TLS Pool,
so beware that the identities provided are not actually validated yet!

A strong possibility of the TLS Pool infrastructure is its ability to
download validation policies from a central source, update its local
policy database accordingly, and have it applied by the TLS Pool without
any interference of the application.  Not having to configure a security
policy in each individual application, but instead controlling it from
a central security cockpit has great impact on manageability of security,
as well as on the ability to demand a general lower bound for security
accross a plethora of protocols and applications.  We suggest to take a
look at the SteamWorks_ project for one infrastructure to distribute
this style of knowledge.

.. _SteamWorks : http://steamworks.arpa2.net


Token PIN entry
===============

The use of tokens stored on PKCS #11 implies that tokens are accessed,
for which PIN codes must be entered.  These may be setup in the
configuration file, but this is not always an acceptable practice for
reasons of security.

Although applications that issue STARTTLS commands could double as
PIN entering applications, this is not generally the advised approach,
again for security reasons; some applications do frivolous things, such
as granting execution control to adverse advertisements or they may be
subject to application-specific complications and programming errors.
It is desirable to move credentials away from programs that engage in
online activities, and if the TLS Pool cannot contain the PIN, it
should facilitate entry of PINs by independent programs.

To this end, a program can access the TLS Pool socket and issue a
PINENTRY command request.  In response to this command, the
TLS Pool can issue a PINENTRY command response, asking for
a particular PIN code.  The user is somehow asked to enter the
said PIN, and another PINENTRY is submitted, this time
carrying the PIN and the callback identity from the PINENTRY
from the TLS Pool to which it responds.

The different formats of PINENTRY are distinguished by
looking at the PIN string.  If it is an empty string, it is not
submitting a PIN and it is merely an offer to pickup on future
PIN validation proposals.  The empty PIN can also be supplied to
refuse entering a PIN; interestingly, the user is usually able
to do this too, and it is often the response to hitting a
cancellation button that scripts may or may not take note of.

If a PIN entry service is to be stopped, the program usually
disconnects from the TLS Pool.  Alternatively, it is possible
to respond to a PINENTRY from the TLS Pool to the PIN
entry application by sending an ERROR with the same request
identity, and expecting to see a SUCCESS response to that.

The TLS Pool supports exactly one program at a time for
PIN entry.  The protocol sketched above will permit for a gap
in the lock for every time a PIN is entered.  To solve this,
the PIN entry protocol supports an additional facility of a
timeout.  This timeout indicates how long it will take the
PIN entry program to respond to a PIN entry request; either
for posting another request over the same socket connection,
or for getting the response back from the user.  As soon as
the entry of a PIN is requested from the program, the timeout
starts running, and until it expires the PIN entry program's
socket is the only channel over which PINENTRY is
accepted.  A secondary PINENTRY channel will not be
put to use until the timeout on the first has expired witout
receiving a response.

This mechanism supports timeouts in case of dying software as
well as solid, long-lasting locks on the PIN entry facility.  It
is up to the application to define the timeout, but it is stated
in microseconds in an uint32_t, so it cannot exceed 4295 seconds,
or a little over an hour.  The value 0 is interpreted in any
special way, it simply means that no timeout is requested.


Local ID Entry
==============

In a manner that is similar to PIN entry, an external program
can also register for Local ID entry.  It might actually be the
same program as for PIN entry, but it does not have to be.

Taking the entry of local identities away from the application
saves it from being configured accordingly.  This also means that
complex models, with dynamically changing local identities and
pseudonyms, aliases, groups and roles are possible without specific 
support for it in applications.  The independency of application
support means that it is the one application for local identity
entry, rather than the least common denominator of all applications
in use, that determines the flexibility and privacy of the local
identities provided to remote peers.

The TLS Pool holds a database that maps remote identities to a
corresponding local identity.  The Local ID entry program can
request to see the available entries before it is being asked to
make a choice, and the selected Local ID can be used to modify
the database.  The database serves as a fallback to use when no
Local ID entry program is being run, and it may in fact still be
used when the Local ID entry program accepts its entries without
further interference.

