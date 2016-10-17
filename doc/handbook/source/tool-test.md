# Testing Tools

>   *A number of simple tools can help the administrator to probe and tickle
>   the TLS Pool.*


## Ping

    Usage: tlspool-ping [socketfile]

The utitility `tlspool-ping` can be used to ping the TLS Pool and thereby
test if it is online.  It runs atop the `tlspool_ping(3)` call of
`libtlspool`.

It may be called with the UNIX domain socket of the TLS Pool, and falls
back to the default path otherwise.

As long as no TLS Pool is accepting a socket connection, the command
will block (but a simple `^C` will get you out).  As soon as it connects,
it will send a ping, holding a specification date, specification source
and facilities supported.  It should quickly get a response from the
TLS Pool, which it will also display:

    Client   specdate: 2015-11-11
    Client   specfrom: api@tlspool.arpa2.net
    Client   facility: starttls
     
    TLS Pool specdate: 2015-11-11
    TLS Pool specfrom: api@tlspool.arpa2.net
    TLS Pool facility: starttls

## Test Client, Test Server

    Usage: tlspool-testcli

    Usage: tlspool-testsrv

These commands are the simplest connections you could make through the TLS Pool,
and they are a great use in testing if TLS traffic actually gets through.
They are used together, and can be started in each order; they will poll.

The client and server connect over TCP port 12345 on `::1`, localhost on IPv6.
As soon as the connection over TCP works, both with delegate their connection
to the TLS Pool, which starts handling each pretty much at the same time.
The TLS Pool won't get confused by that, but when reading any debugging or
logging output, keep in mind that two sessions are running virtually at
the same time.

The tools also test a lot of special functionality of the TLS Pool, such as
detaching and reattaching of connections (this can be used in programs to
pass a succeeded TLS connection to another process in a controlled manner).
It even tries to do things that are not supposed to work, and ensures that
this responds as expected.  You should not see anything of this, at least
not if it all works as expected.

Once the programs run, you can type lines, which will then be passed through
TLS over the local connection to the other side, which displays the lines
promptly.

As a special facility, you can use `^Z` to suspend the test program.
When it comes back up after `fg`, it will renegotiate TLS, leading to
fresh keys being agreed.  Again, you should not notice if this works
as expected.  We did notice during development that the most reliable
method of doing this is within the `gdb` debugger, rather than directly
in the shell, though.

A future variation on these programs will be called `tlspool-testpeer`; it
will simulate peer-to-peer connections, where TLS is used symmetrically,
as per [draft-vanrein-tls-symmetry](https://datatracker.ietf.org/doc/draft-vanrein-tls-symmetry/).

