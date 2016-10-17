User Interface: Identities and Visibility
=========================================

>   *The user interface is intended for direct communication with the user, for
>   example through a graphical interface.  The two kinds of interactions needed
>   at least are a PIN entry exchange, and the selection of a local identity and
>   to which remotes it may be revealed.*

An assumption that is (currently) made by the TLS Pool is that servers are
always revealing their identities to any clients; but that clients may want to
hold back on what part of them they reveal to servers:  To a music site I might
want to be a Kate Bush fan, while towards the tax office I might want to show
another side of me.

To facilitate this, the user interface implements an interaction known as the
local identity service, through the library call `tlspool_localid_service(3)`.
This is a registration that will evoke callbacks when a choice of a user
identity is to be made.  There is a great variety of situations in which this is
desired, and flags can be used to control just that.

When a local identity callback is made, the principal concerns of the TLS Pool
are:

-   What local identity can I reveal to the remote identity of the current
    session?

-   Can I reveal the identity to a more general
    [selector](http://donai.arpa2.net/selector.html) than just the remote end
    point?

The user is presented with a popup to ask precisely that.

A very, very mundane implementation of this facility is included with the TLS
Pool as [lidsel.c](https://github.com/arpa2/tlspool/blob/master/tool/lidsel.c) —
but any sane person would prefer a nicer interface, like the default [TLS Pool
GUI](https://github.com/amarsman/tlspool-gui).

The other aspect presenting interactions to the user is the PIN entry.  For
this, a simplistic implementation is provided in
[pinentry.c](https://github.com/arpa2/tlspool/blob/master/tool/pinentry.c), but
again most users will prefer the [default
GUI](https://github.com/amarsman/tlspool-gui) instead.

The mechanism for PIN entry is similar to that for local identity selection,
namely a registration for callbacks, this time through library call
`tlspool_pin_service(3)`.
