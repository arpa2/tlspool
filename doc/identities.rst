Identity Management with the TLS Pool
=====================================

*TLS Pool can support an access method where external parties only see the
roles of a local user.  This is facilitated through a distinction between
internal and external identities.*


Concept: Individual Users and Groups/Roles
------------------------------------------

User identities are used, among others, to identify human beings.  In addition,
there may be separate identities for machines, services and other automated
processes; but there are also systems where these are combined with user
identities.  The main thing that the TLS Pool extracts from this is the notion
of an **individual identity**.

A special form of individual identity is an **alias** or **pseudonym**, which
is a well-established identity that differs from an individual identity,
but either maps to it or is equivalent to it.

Really different from individual identities are **groups**, which are
functionally similar to **roles**.  When describing the TLS Pool, we use the
term **group identity** for both.  As with individual identities, there may be
other views on the matter that interpret the two notions as distinct.

In fact, none of this is supported directly by the TLS Pool, but a suitable
concept and protocol to base it on is, to support this style of identity
management and thus enable explicit control over privacy through the TLS Pool.


Concept: Public and Private Identities
--------------------------------------

In any system, there may be identities that are considered public, and
others that are considered private.  For instance, administrative
group identities may be considered a strictly internal matter, and
individual identities for account access could be too.

Whether an identity is public or private is not related to whether the
identity is represents an individual or a group; there may be a stronger
tendency to use role names (so, some group names) externally, but this
need not always be the case.

Even when an identity is considered public, this may only be to one or
a few remote peer identities.  This is highly subjective, but it is
useful to be able to signify local identities and their publication
to certain remote peers.

Again, the concepts of public and private identities are not supported
directly by the TLS Pool, but an underlying concept that permits their
implementation is included because the concept is supported.


Misconception: Client and Server Identities
-------------------------------------------

The TLS Pool deliberately does not distinguish client and server identities.
The initiative of communication is a mechanistic matter, but should not be
material to identity handling, other than for access control.  Not all parties
that we access may have access to us, but that does not mean that their
identities should change because of that.

The distinction between a client and server is now strictly a matter of who
takes the initiative to communicate.  This makes TLS more consistent with
TCP, which can also be setup in two directions.  Some higher-layer protocols
do not distinguish between the client and server roles, and when they run on
top of TLS this could get curious.  An example is MSRP, which permits both
sides to push chunks of MIME-typed data.  Another example are connections
that do make a distinction between client and server roles, but that might
be setup in both directions; examples are connections
between domain servers for SMTP, XMPP and SIP; these protocols call for a
connection by the side that needs to take the initiative.

The TLS Pool is actually trying to pave the way towards a more symmetric
approach to TLS, where we speak in terms of local and remote identities,
and whether they are to be authenticated.  The party taking the initiatice
may be left to the TLS Pool (given a suitable small adaption to the TLS
protocol to favour symmetric application protocols).  The entire API design
has been updated to reflect this symmetry.

In practice, client identities are not always required and when they are
they take the form ``user@example.com`` while servers often use the identity
of a domain such as ``example.com``, so there are other places that show
the distinction -- but this is a mere practice for which no strict general
requirement exists.  In the general terms of the TLS Pool API it is said
that a domain may identify on behalf of a user underneath that domain.  This
is common practice; for instance a mail server is generally trusted to be
under sufficiently tight administrative control that it would reliably
represent its users.


Mechanism: Internal and External Identities
-------------------------------------------

The implementation concept that the TLS Pool supports in terms of identities
is a possible distinction between **internal identities** that will not
normally be shown to the outside world (at least not without confirmation)
and **external identities** that are considered visible to outside
entities.

This is implemented with a possible callback scheme that triggers whenever
a local identity is to be shown to the outside world.  Based on a disclosure
database that may contain previously approved published local identities,
and possibly making a callback to a "lidentry" program, the user can control
whether a local identity is sent out to a remote peer, or whether it will
be replaced before it is sent out.

Specifically note that the TLS Pool contains no rules to reason
like "matching domain names" in remote and local identities to
establish whether a remote peer should be considered local.  This
is left up to the confirmation mechanism, which is free to setup
any such rules, or let a user make the choices.

Confirmation means that a backcall is made to the client, through the "lidentry"
mechansim, to select the identity to use.  The backcall puts the client in the
position where it receives a suggested local identity, and is
in the position to replace it.  The mechanism is the same as
used when no local identity was provided initially by the client,
except that a suggestion is made in the form of the internal
identity.

The new identity may be undefined in the local identity database,
in which case it can be added by setting the proper flags.  Any such
addition will only be stored on disk when it succeeds in setting up
the TLS connection.


Mechanism: Constrained Disclosure
---------------------------------

The mechanism of constrained disclosure filters the visibility
of local identities to remote peers.  It is based on the name, or a
generalising pattern, for the remote peer.  The patterns take the
shape of a `DoNAI selector`_

When a remote identity arrives at the TLS Pool, it is looked up
in the disclosure database to find local identities that it may use
against that remote identity.  When a local identity is freed
for use against a remote identity, it may actually be freed
against a DoNAI selector that generalises that remote identity,
and it will then be permitted at that level.

When acting as a TLS client, the TLS Pool uses the remote identity
as provided by the user to lookup local identities that may be
used.  The first match found is used.


Extension Mechanism: Application Interface to Disclosure
--------------------------------------------------------

The TLS Pool supports user interfaces that help to modify the local
identity provided.  This mechanism replaces the use of the
disclosure database, but it can also extend it.  What exactly happens
is determined by the user interface application.

The extension application will most often act as an extension to the
disclosure database, although it may be made so powerful that it
completely replaces that database.  There are various flags that can
be used to influence the disclosure registration:

 * The application may indicate that it wants to be told about database
   entries.  Without this indication, only the remote identity and any
   app-suggested local identity will be provided in a callback to the
   extension mechanism.  However with this indication, this callback is
   preceded by a series of zero or more callbacks with database entries.
   These can be used by the extension to populate menu structures.  In
   all cases, the remote identity is set to the concrete DoNAI value,
   plus the number of levels up until the database entry found,
   counted by the iteration procedure for DoNAI Selectors.

 * The response from the extension indicates whether the returned setting
   should be setup in the database.  In this case, the remote identity may
   be either the concrete DoNAI or a DoNAI Selector, as long as it is not
   more than the permissible levels up from the concrete DoNAI.  It is
   possible for the extension to provide the remote identity in a pulldown
   menu, permitting generalisation up to the permissible level.

 * The extension may register to only be contacted when the disclosure database
   has no entries available, or when it has to reach up to a certain level.
   This may indicate too-abstract forms in the DoNAI Selector iteration;
   most likely, one wants to restrict to one subdomain level, and perhaps
   disallowing the root patterns.  Flags can do this; one flag to disallow
   dropping of usernames, one flag to disallow one level up from the domain
   name; one flag to disallow more than one level up from the domain name; and
   one flag for disallowing the root level.

 * The extension can be used to indicate a preferred identity.  To this end,
   insertions into the disclosure database may be placed in front of, or after
   current entries.  There is also an indicattion for reordering existing
   entries.  The idea of a default however, is local to the extension.  This
   means that it can decide how to weigh ordering in the disclosure database.

 * Something the disclosure database does not support, and might go into an
   extension, is a translation of a currently considered (or user-selected)
   local identity to an identity that is disclosed to the remote.  The local
   identity may be used as a pathway to accessing that disclosed credential.
   This probably calls for a database that is kept external to the TLS Pool;
   namely, one that lists aliases, pseudonyms, groups, roles for local
   identities that one uses during login.

 * Future versions of the extension API may include mechanisms for on-the-fly
   generation of credentials (new local identities confirmed by an already
   existing credential) and perpahs even the generation of new credentials that
   will be locally or generally available for an indicated time.  Such one-shot
   identities may be used for light-weight aliasing.  The vital concern with
   this type of mechanism is that the public sides of such credentials should
   also be published somehow, such as through LDAP or DANE, and it is undecided
   who should take the responsibility for such publications, and how to
   communicate it from a TLS Pool endpoint to a central identity publication
   node.  Since TLS Pool currently is a readonly user of public and private
   credentials, we may choose to leave this to the extension application
   instead of to the TLS Pool, and to support it through synchronisation
   mechanisms for reception of the new credentials.  Note that identities may
   have limited use also; for instance, they may be just receiving mailboxes,
   available for as long as a client is subscribed to them on the mail server.

 * Future versions of the extension API may include mechanisms to delete
   entries from the disclosure database, and/or rename them to more general
   or more specific entries.  At present, the API is intended for user
   interfacing and such editing abilities seem too complex to unleash on
   end users, but we may feel differently about this later on.

