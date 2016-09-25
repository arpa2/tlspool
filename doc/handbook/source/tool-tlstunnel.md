TLS Tunneling Tool
==================

>   *The tlstunnel is a wrapper around connections that simply adds (or removes)
>   a TLS wrapper. The tool is generic, and can even engage in STARTTLS
>   handshakes. The one thing it cannot do is reveal the authenticated
>   identities to the plain-connected endpoint.*

The TLS Tunnel is a generic tool, and does things similar to
[stunnel](https://www.stunnel.org/static/stunnel.html), except that its driving
engine is the TLS Pool. It is extensively documented on the `tlstunnel(8)`
manual page. It can run as a client or server.

TLS Tunnel wrapping TLS around a Server
---------------------------------------

One possible use is to wrap an unprotected web server, using the TLS Tunnel to
receive incoming connections with TLS, remove the TLS wrapper and forward to the
plaintext web server. This can be done with

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tlstunnel -s -l [::]:443 -L testsrv@tlspool.arpa2.lab -r [2001:db8::1234]:80
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The parameters indicate:

-   `-s` for server mode

-   `-l [::]:443` is the local address; in this case, it listens to all local
    network interfaces, specifically on TCP port 443, for incoming TLS
    connections

-   `-L testsrv@tlspool.arpa2.lab` is the identity used on the local end; it
    represents the server over TLS

-   `-r [2001:db8::1234]:80` is the remote address, in this case the plaintext
    web server

The identities used are not very practical; they actually stem from the test
setup for the TLS Pool; but you can of course insert your own; you can use
identities with or without a user and `@` symbol.

TLS Tunnel wrapping a Client into TLS
-------------------------------------

Another possible use of the TLS Tunnel is to take a plain text connection and
wrap it into TLS. This can be done with

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tlstunnel -c -l [::1]:8080 -L testcli@tlspool.arpa2.lab -r [2001:db8::1234]:443 -R testsrv@tlspool.arpa2.lab
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The parameters indicate:

-   `-c` for client mode

-   `-l [::1]:8080` is the local address; in this case, it listens to localhost,
    specifically on TCP port 8080, for incoming plaintext connections

-   `-L testcli@tlspool.arpa2.lab` is the local identity; it represents the
    client towards the server over TLS

-   `-r [2001:db8::1234]:443` is the remote address; it might be one of the
    network addresses to which the server-side TLS Tunnel from the previous
    section listens

-   `-R testsrv@tlspool.arpa2.lab` is the remote identity; the client-side TLS
    Tunnel will validate this to authenticate the server

The identities used are not very practical; they actually stem from the test
setup for the TLS Pool; but you can of course insert your own; you can use
identities with or without a user and `@` symbol.

Bootstrapping STARTTLS methods
------------------------------

An example of wrapping a web connection is a bit trivial; these connections run
their TLS variants over a separate port, and will engage in the TLS handshake as
soon as they are connected.  Most other protocols follow a more modernised
method, where they initiate in a plaintext connection, and possibly after
negotiating features they will initiate a STARTTLS command.  Once both ends
agree to this, the TLS negotiationn starts.

The manner in which this is done differs widely across protocols.  Still, the
general idea is very special, and given that we know the remote endpoint we also
know what exchange works for it.  An example for SMTP would be:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
S: 220 mx.google.com ESMTP vw1si18189807pac.278 - gsmtp
C: EHLO tlspool.arpa2.nep
S: 250-mx.google.com at your service, [2001:980:93a5:1:1031:235a:e456:5ff9]
S: 250-SIZE 157286400
S: 250-8BITMIME
S: 250-STARTTLS
S: 250-ENHANCEDSTATUSCODES
S: 250-PIPELINING
S: 250-CHUNKING
S: 250 SMTPUTF8
C: STARTTLS
S: 220 2.0.0 Ready to start TLS
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Lines marked with `S:` come from the server, and `C:` indicates client-sent
lines.  Note how the server at some point indicates with a line `250-STARTTLS`
that it offers the facility to issue a command `STARTTLS`, which the client does
indeed.  Then, the server responds positively (with `220 whatever`) and after
the end of that response the connection transcends into the TLS handshake.
After having succeeded, the TLS-wrapped connection starts from scratch, because
anything exchanged prior to the `STARTTLS` command was not protected and is thus
not reliable.

The TLS Tunnel can participate in such exchanges prior to the actual TLS
connection having started.  To that end, it pulls an old work horse out of the
meadows, namely `chat(8)`.  In the early days of the Internet, when we used
dial-in modems, we used this language to describe the stimulus/response
interaction with our Internet provider’s modem pool.  This was done to establish
our username and password before we were allowed to start `ppp` and continue
with IP activity.

The example script to achieve this for an SMTP server is included in the TLS
Pool distribution’s `extra` directory; we include it here to give an idea of the
type of script that can interact with a server like the one above,

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ECHO ON
TIMEOUT 10
"220 " "EHLO example.org\r\n\c"
"250-STARTTLS" "\c"
"250 " "STARTTLS\r\n\c"
"220 " "\c"
"\n"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes, simple solutions work best :-) and the result in this case is
excellent: you end up having a local connection that looks like the plaintext
thing, but the wrapper does everything necessary to wrap a layer of security —
including this initial incarnation to get to the TLS handshake.

Limitations of a generic TLS Tunnel
-----------------------------------

The TLS Tunnel is a useful utility, especially to system administrators. But it
is not a complete TLS solution, and it is important to be aware of the
limitations. The generic nature of the TLS Tunnel defines both its broad
usability and its inherent shortcomings.

In many applications, it is desirable to know the remote identity, so as to be
able to switch behaviours. This may apply to situations with clients who
identify over TLS and then are freed from the burden of manual login procedures
that are run within the unreliable context of a web interface.

Note that the TLS Pool makes an effort to facilitate this mode of use; [local
identity selection](tool-lidsel.html) helps to control this, the link to
[SteamWorks](innov-steamworks.html) helps with remote provisioning of identities
(currently a major problem to making certificates practically usable), and
additional mechanisms [OpenPGP](innov-pgp.html), [TLS-KDH](innov-tlskdh), [SRP
\#11](innov-srp11.html) and additional protocols such as [STARTSSH and
STARTGSS](innov-proto.html) help to make it ever more likely that clients can
find a pragmatic technology to provide their identity over TLS.

Such identities cannot be shared from the TLS Tunnel to a plaintext client or
server; the reason is simply that each of the plaintext protocols is different,
and the TLS Tunnel is a generic solution. So, when the remote identity matters
(or when control over the local identity is desired), the TLS Tunnel is not the
best choice.

The best solution is and will always be the integration of the TLS Pool with a
target application. This is why webservers have plugin modules, for example.
Interestingly, it [takes about an hour](prog-saved) to add the TLS Pool to an
application, and to retrieve the authenticated identities from the TLS handshake
— so we provide the TLS Tunnel but really just see it as a stepping stone
towards better integration with services.
