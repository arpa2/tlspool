Switching Protocols
===================

>   *Plan to throw one away — it is an old wisdom.  Where TLS is concerned
>   however, we see problem after problem but we have no way of throwing it out.
>   Not if we mean to continue service levels.  The solution may be to be more
>   supportive of other protocols that can achieve similar security levels, such
>   as SSH or GSS-API based protocols.  The TLS Pool innovates this idea by
>   being supportive of alternate backends than just TLS.  And by making it a
>   very predictable plugin in everyday protocols.*

The TLS Pool has a command named `tlspool_starttls(3)` for turning an existing
network connection socket into an encrypted socket, and ending up with a new
socket that can be used as a fresh plaintext socket — except that we know that
this new socket is being protected by the TLS Pool.

The same mechanism can be mapped with relative ease to other security protocols.
A few candidates have been defined in the IETF; notably SSH and the various GSS
protocols.   The TLS Pool is supportive of these additional protocols, which are
usable in a manner that is highly comparable to the TLS variant — though not
quite, there are bound to be small changes and the choice between TLS, SSH and
GSS must be made explicitly.

This explicit choice reflects what a client program usually goes through.  Most
protocols have some form of a `STARTTLS` command, which must be confirmed before
the two endpoints engage in a TLS handshake.  Before issuing the command, there
often is a negotiation that indicates support of the command.

In a similar fashion, protocols might have features for `STARTSSH` and
`STARTGSS`, with similar API calls to the TLS Pool.  The TLS Pool indicates
whether backends for these extra protocol initiations are supported, and the
application can ask for this during a `tlspool_ping(3)` interaction.

**TODO:** The TLS Pool currently only has a backend for TLS, the alternatives
have not been implemented yet.
