STARTTLS, STARTGSS, STARTSSH
============================

>   *The TLS Pool was designed to capture TLS connections, and take away all
>   security-specific concerns from applications.  This has succeeded so well
>   that it is actually possible to support other secure connections besides
>   TLS, namely GSS-API based connections and SSH.  Having an alternative when
>   the TLS protocol itself fails can be tremendously useful.*

If a vital design issue in TLS would hit the fan, we have nowhere to go in
the current situation.
Our websites are insecure, or secured by TLS, and that is it.  The design of
TLS is sufficiently complex ot make this a matter of some concern.

There are alternative secure transports that can be used as a protective
cover around a plaintext connection, namely the
[OpenSSH](https://tools.ietf.org/html/rfc4251)
protocol, and it
is also straightforward to pass
[GSS-API](http://tools.ietf.org/html/rfc2743)
frames in a protocol.  These
can form a serious alternative, especially when their method of establishing
local and remote identities is integrated with the
[DoNAI](http://donai.arpa2.net)
format used by TLS Pool applications.

Note that application programs do not even need to be aware of this.  Our
suggested use of the
[SASL EXTERNAL](http://tools.ietf.org/html/rfc4422#appendix-A)
method to lookup or verify against the
identities supplied by the TLS Pool authentication process is consistent
because it is impartial to how the TLS Pool obtained an identity.

The only thing that the application must tell to the TLS Pool, is that it
wants to use a given socket for one of the other protocols, and not TLS.
So the STARTTLS command sent to the TLS Pool would be varied; it would be
made into STARTSSH, or STARTGSS.  This is an extension that is not yet
defined in the API, but we anticipate defining it in a follow-up.

In preparation of such extensions, we have defined a "facilities" bitfield
in the PING command.  This can be used to negotiate which of the STARTTLS,
STARTGSS and STARTSSH facilities are available to both the TLS Pool and its
client.

Note that this negotiation is going to be very useful if an application
is to support the alternative secure transports.  Commonly, an explicit
STARTTLS or <starttls/> or similar command is exchanged between the
application end points, followed by the initiation of the TLS protocol
over what was up to that point a plaintext connection.  Although it would
involve standardisation effort, it should not prove
too difficult to introduce alternate commands such as STARTSSH and STARTGSS
for the various applications that now support STARTTLS, but the resuts of the
PING negotiation are needed to be able to inform the remote application
end point about its options, as well as to know which ones from a remote
offering of alternative secure transports may be tried.


