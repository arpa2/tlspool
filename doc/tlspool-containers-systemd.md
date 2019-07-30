# TLS Pool and Containers

> *POSIX systems are quickly converging on container
> technology and central coordination of processes
> with systemd.  This offers a great opportunity for
> plugging in a TLS Pool.*

We have always wanted TLS logic to reside separately from the application logic, and started the TLS Pool as an initiative to get it into a separate process.  This concept can be further hardened by everyday container technology, which effectively splits up the name spaces of a host such that processes can only look into those parts of one another that they are permitted to see.  The kernel validates this property.  Having been an [early adoptor]() in this arena, even predating Docker, our initiating developer really ebraces this movement.

## Why the TLS Tunnel solves a part

The TLS Tunnel we made for this purpose can do some of this, but not all.  It can be used for the plaintext portion of several protocols up to the point of `STARTTLS`, after which is passes on a protected connection:

```
C: a001 CAPABILITY
S: * CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED
S: a001 OK CAPABILITY completed
C: a002 STARTTLS
S: a002 OK Begin TLS negotiation now
```

It is possible at this point to start TLS negotiations and pass on the thusly protected connection to the IMAP server that only needs to think in terms of application logic, and not care about TLS at all.  It will never see plaintext traffic if IMAP always comes in to the TLS tunnel.  And the mechanism is such that the connection only passes through one intermediate process, being the TLS Pool.

This sounds good, but it is not enough.  There are points where interaction with an application is needed:

  * Possibly check if a server name proposed in TLS SNI is acceptable
  * Usually to pass in the negotiated name of the server
  * Possibly to pass in an identity of the client
  * Possibly to renegotiate about client identity

## Proxying TLS Pool messages

All these things are taken care of by the message exchange between the TLS Pool and the TLS Tunnel.  In the simplest use case, the application needs none of this and can just do its thing, having convinced the client that it is a trustworthy party.  But for more advanced uses, and those even occur in HTTP, more interaction with the TLS Pool is required.

This can be resolved with a small change of mind, however!  Instead of connecting to a port on the backend server from the TLS Tunnel, we might hand it a TLS Pool communication that holds a file descriptor.  When it is passed over a UNIX domain socket, the file descriptor can be communicated to another process, as we already do for TLS Pool operations; this is a lesser-known part of POSIX standardisation which has shown to be reliable.

So what remains is this:

 1. Configure the TLS Tunnel with not just a protocol, but also flags and such for the STARTTLS request
 2. Once connected, pass the result of STARTTLS to the backend server, *with the file descriptor and control key present*
 3. When the backend wants more, they can communicate with the TLS Pool
 4. The backend can have its own TLS Pool connection (and use the control key, after the TLS Tunnel detached) or it can talk back to the TLS Tunnel, which would relay the request to the TLS Pool and relay back the answer
 5. Only the TLS Pool is an intermediary for the TLS traffic; however for negotiations the TLS Tunnel remains active

The result is now that we can service all protocols with a STARTTLS facility, including the simplest ones like HTTP that do have special desires in some cases.

## TLS Tunnel -> TLS Proxy

We used to speak of the TLS Tunnel, which was modelled after the SSL Tunnel.  It now seems that we are diverting, and a new name probably adds clarity to that distinction.  The new name would be TLS Proxy.  The preceding TLS Tunnel can be reincarnated as a mechanism based on the TLS Proxy, though its use should really be deprecated -- and therefore also its name.

## Adding to Containers and Systemd

If we look at the `runC` program, which implements [Open Containers](http://opencontainers.org), and specifically its [handling of file descriptors](https://github.com/opencontainers/runc/blob/master/docs/terminals.md), we see that it follows [socket passing in systemd](http://man7.org/linux/man-pages/man3/sd_listen_fds.3.html).  These mechanisms separate connection-making from application logic, and the TLS Pool is just an extension of that idea.

The implementation of such a variation in the TLS Tunnel scheme can both simplify the application at hand, separate out its need to configure plaintext handling (and therefore any chances of confusing it with secure handling) but it does retain the full potential of the TLS Pool for those applications that want it.  To those that only need a bare minimum, we can simply pass in a handle as in the original design.

## A modest Application Library

For the more advanced use cases, we can use what we have a TLS Pool API, without change.  The application does not notice whether traffic passes through a TLS Proxy.

The one thing that changes is how we get new connections.  The normal usage pattern is to call `socket()`, `bind()` and `listen()` or, in the case of socket passing for containers or systemd, this has already been done.  Then, one proceeds with `accept()` to reap incoming connections.

The new paradigm would replace the socket setup phase with one for the TLS Pool.  Currently, that would be done in the TLS Pool library.  In a socket passing style, a TLS Pool socket or a TLS Proxy socket may be passed in.  Then, one proceeds with `tlspool_accept()` -- a new API call mimicing the `accept()` call in its pattern of use.

There is an option of TLS Pool descriptive information in this phase however, and that would be stored in a structure that may be passed in.  Applications without the need of such information can pass in NULL at this point, and the information would be dropped.

As explained, a few extra facilities may be needed, such as interactions about the acceptability of a SNI-provided server host name.  These would only come in when the TLS Tunnel was configured with the flags causing them.  If they occur, they can be handled irrespective of the connection to which they apply, as it predates secure connections and the TLS Pool ensures passing the right information along with the right socket to accept.