Local Identity Selection
========================

>   *When the TLS Pool supplies a local identity to a remote peer, it might
>   be sharing an identity that you consider private.  This means that the
>   end user should have some control over which local identity to send.*


Multiple local identities, managed from one place
-------------------------------------------------

The TLS Pool has been designed to support a variety of local identities,
even for the same party.  Among the
[forms of identity](http://internetwide.org/blog/2015/04/23/id-3-idforms.html)
supported are pseudonyms, aliases, groups and roles.  The identity to
supply to a remote peer may vary, and should be customisable.

This customisation is not a responsibility of an application.  Imagine that
a user would change their primary identity from a work identity to a private
identity.  This would also mean that the available groups, aliases and so on
change.  If the primary identity would be changed in applications, this would
have to be changed in each application separately: the web browser, mail client,
chat tool, telephony and so on.  It is much simpler to do this centrally for
all applications at once.  In addition, this means that it is easier to
enforce identity changes without depending on applications to co-operate
(read: have implemented this advanced behaviour).

For this reason, the TLS Pool allows one "lidentry" tool to register on
behalf of the client for which it is active.  This tool will be asked to
provided identity information, following whatever logic it deems useful.

Fallback support: Database
--------------------------

When no "lidentry" tool has been registered with the TLS Pool, it still has
something to fallback on, namely its database that matches the remote identity
and searches for an accompanying local identity.  For a client, the remote
identity is usually specified because it is the service being connected to,
but for a server the remote identity is unkown and so the most general
pattern must be supported, that is, `.` and `@.` in
[DoNAI](http://donai.arpa2.net)
notation.

When there is a "lidentry" tool, the database entries are supplied to it,
followed by a request to make a choice.  Alternatively, when registering
the "lidentry" tool, a flag may be set to indicate that the callback to the
tool is only done when the database supplies no information.

Persistent Choice of Local Identity
-----------------------------------

It would be a nuisance if local identities would have to be selected over
and over again; it is pleasant to be able to say "remember this choice"
and indeed, that is what the TLS Pool supports.

The mechanism works through flags added to the selected identity in the
"lidentry" tool.  Flags may be set to add the choice to the database, and
that might mean that the next time the TLS Pool can decide for itself
what identity to use.  The choice of a local identity is only stored in
the database when the TLS transaction fails with the made selection.

It is possible to specify the remote identities to which the to-be-stored
local identity applies.  This is done by setting the remote identity to a
[DoNAI selector](http://donai.arpa2.net/selector.html)
that captures at least the requested remote identity.  So you can setup
a local identity to always be used when approaching `.webshop.nl` or
something similar.


Advanced use: On-the-fly Certificate Generation
-----------------------------------------------

One possible use of the TLS Pool is as a TLS Proxy; or more specifically,
for protocol-specific proxies that mangle the application traffic.  For
instance, think of a HTTP proxy that filters for privacy.

To make this possible, TLS connections must be setup with an identity that
is acceptable to the end user's client, but that end on the TLS Proxy
instead of at the designated server.  This is possible as long as the client
accepts a root certificate under which the proxy generates certificates
on the fly.  (This is complicating, for good reasons -- it would be a mad
world if anyone could be a proxy and apply man-in-the-middle attacks.)

The TLS Pool lets you specify a certificate and key that will be used
for on-the-fly certificate generation.  And the "lidentry" tool can specify
that this should be done with a special flag in its returned information.
Usually, either an application or the Server Name Indication sent to a
TLS server will be available as a suggested identity, and the "lidentry"
would basically approve that identity.

**Note:** This behaviour is currently specified in the API, but it is not
yet implemented.  The error response will match the response given when
no signing certificate and key were configured.


Advanced use: New Credential Generation
---------------------------------------

In yet other applications, one can think of generating a certificate
on the fly.  Now consider that the infrastructure of the TLS Pool can
be distributed, and that external tools may need to be started when
this is desired.

Such external interactions may be started by the "lidentry" tool, but it
should not block to wait for them; after all there is just one such
callback interface, and blocking that would stop all other connection
attempts that need to ask questions through it.  The limited interface
is entirely due to the single-threaded minds of human users, by the way.

So, rather than blocking until the new credential has been created (and
hoping that no intermediate delays exist to pass it on to the TLS Pool)
the "lidentry" tool will report back the new identity, and set a flag to
signal that it is being created, and may need some polling.

To use this, a graphical interface could list existing identities that
might be sent in a pulldown menu, and add an entry "other: specify" that
allows the entry of the new local identity, and fire off whatever it can
do to create this identity.

**Note:** This behaviour is currently specified in the API, but it is not
yet implemented.  The error response will match the response given when
the repeated lookup of the credential hits a timeout.


Demo tool: lidsel.c
-------------------

The TLS Pool code includes a simple demonstration "lidentry" tool, namely
as tool/lidsel.c -- it works on the commandline, provinding a listing of
database entries that might apply, and subsequently asking to choose one
or to enter a local identity.

This is a rather basic tool, but it does serve to demonstrate the principle.

