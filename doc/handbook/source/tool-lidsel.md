Local Identity selection Tool
=============================

>   *When a connection to a remote is made, the TLS Pool can vary the local
>   identity that is being used.  It can store such choices, or ask once more
>   during the next round.*

The TLS Pool has a separate API for selection of local identities, built atop
the `tlspool_localid_service(3)` of `libtlspool`.

In preparation of the selection being made, the TLS Pool sends a number of
callbacks with options that it thinks are possible, and it ends by asking what
local identity should be chosen.

Database storage
----------------

The TLS Pool can store choices made in the `disclose.db`, and as part of the
response the local identity selection can indeed request the storage of the
information in that database; which will be committed only when the TLS
handshake succeeds.

Storing selections in a Database
--------------------------------

The TLS Pool searches upward through the `disclose.db`, following the scheme of
[DoNAI Selectors](http://donai.arpa2.net/selector.html), starting at the most
concrete and rising to evermore abstract ones.  If no match is found, then a
callback may be needed, although it is also possible for programs to register
for callbacks in spite of the state of the database.  When picking a local
identity, the user can select the DoNAI Selector to apply, so as to match a
broader range of remote peer identities than just the one that happens to be
involved in the current interaction.  The TLS Pool will ensure that no entries
can be written that are so abstract that another database entry blinds it.

A practical use that will suit most users is probably to let the TLS Pool do its
thing based on the database whenever possible.  Then, when the database yields
no response, it will call back to the local identity selection program, and
offer choices.  The user will select an entry and may indicate *remember this
choice* which would request storing it in the database.  The choice is not just
the selection of a local identity to use, but it may also set the remote
identity to a somewhat more abstract form; the TLS Pool indicates in the request
how many levels up in the abstraction level of the DoNAI Selector for the remote
would be acceptable (higher-up levels would be clouded out by existing
definitions in the database).

Privacy precautions
-------------------

The choice how to appear to a remote peer may be somewhat privacy-sensitive, and
to evade problems with that, the TLS Pool takes a number of precautions when
allowing registration for the service:

-   only one program can register at a time, presenting an intended response
    timeout

-   to stay registered, a program must keep its connection to the TLS Pool

-   to stay registered, a program should respond within that timeout

A user interface may show the timeout as a counter, a progressing bar, or
whatever else makes sense to users — or it may simply autorespond with the
current or initial selection just before the timeout.

Cut-and-dry text mode Local Identity Selection
----------------------------------------------

>   `Usage: tlspool-lidsel-textual`

A minimalistic implementation of local identity selection is supplied with the
TLS Pool, as `tlspool-lidsel-textual`.  It runs on a command shell which it
occupies, and on which any requests to select a local identity for the TLS Pool
will be shown.  The tool presents a menu and awaits a choice.  It does not
enforce the timeout, so it may fall out of grace when a response comes too
slowly.

Graphical User Interface
------------------------

A dedicated project for local identity selection for the TLS Pool is provided in
[tlspool-gui](http://github.com/amarsman/tlspool-gui), where it is paired with
[PIN entry](tool-pinentry.html).
