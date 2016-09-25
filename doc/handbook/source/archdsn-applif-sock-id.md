Application Interface: Sockets and Identities
=============================================

>   *The face that the TLS Pool shows towards an application is modest, and
>   certainly simpler than the customary tasks that the application faces. In
>   essence, the application need only be aware of sockets and identities.*

Applications feel a need to initiate TLS at some point during the execution of a
network connection; either right when it is started (such as for HTTPS) or after
a certain exchange (such as the STARTTLS command in IMAP, SMTP, XMPP and LDAP).
It is at this point that the application initiates contact with the TLS Pool.

The TLS Pool itself is a daemon that listens on a UNIX domain socket (on
Windows, this is replaced by a `NamedPipe`). In principle, the previously
unencrypted connection is passed over this interface to the TLS Pool, which then
initiates the TLS handshake. The application and TLS Pool setup a
`socketpair(2)` between them that will carry the plaintext traffic, resulting
from the TLS Pool's endeauvours in removing TLS.

Not many know this, but passing file descriptors (such as sockets) over an
`AF_UNIX` socket is a POSIX standard, and thus available on most platform. The
one platform that is (or was) not POSIX-compatible is Windows; there, a similar
mechanism can be simulated by passing a `HANDLE` between `Process` instances.

Although the [socket-level
protocol](https://github.com/arpa2/tlspool/blob/master/doc/socketprotocol.rst)
between the application and TLS Pool has been described, it is subject of [some
developments](https://github.com/arpa2/tlspool/issues/42) and it is likely to
[change in the
future](https://github.com/arpa2/tlspool/blob/master/doc/socketprotocol-future.md).
For the time being, the advised interface is therefore to go through the TLS
Pool library, whose calls should be more stable over time. This library is also
the main target for language porting, because it delivers better maintainable
language ports than reinventing the socket protocol in each language.

In essence, the communication between an application and the TLS Pool is a
request to take a socket and STARTTLS on it; this is embellished with parameters
and settings. Once the handshake is complete (or has failed), a response (or an
error) will be reported to the application. The response will include a local
and remote identity, authenticated by the TLS Pool as part of the TLS handshake,
and so a solid basis for further processing in the application. Usually, the
next step for the application will be to subject the remote identity to
authorisation inquiries, usually guided by [access control
lists](http://donai.arpa2.net/acl.html).

The details of this interaction are documented in the following manual pages:

-   `tlspool_socket(3)` — Setup the TLS Pool to use with a given socket path

-   `tlspool_ping(3)` — Negotiate version and features with the TLS Pool

-   `tlspool_starttls(3)` — Switch wrapping a plaintext connection into TLS

-   `tlspool_prng(3)` — Pseudo-Random Number Generation from TLS master secret

-   `tlspool_control_detach(3)` — Detach a TLS connection from the current
    process

-   `tlspool_control_reattach(3)` — Reattach a TLS connection to the current
    process

Of these, the main function is `tlspool_starttls(3)`, and the data structure
`tlsdata` passed in and out of it defines the identities exchanged; the rest of
the manual page explains the varieties of sockets passing in and out.
