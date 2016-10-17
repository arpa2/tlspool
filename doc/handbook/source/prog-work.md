Work Saved, Work Left
=====================

>   *The TLS Pool saves programmers a lot of work.  What remains to be done?*

Many open source projects understand the need for security, and place TLS on the
TODO list.  It may remain there for quite a while, for the simple reason that it
raises complexity.  The following issues are on the usual list of
responsibilities, and taken away by the TLS Pool:

-   Configuring identities (in the form of certificates and keys)

-   Loading these identities into the TLS stack

-   Interacting with the TLS stack

-   Dealing with two kinds of protocol interaction; either with or without TLS

-   Validating the remote identity (if applicable)

-   Choosing from the many, many variations that TLS supports

-   Validating that TLS has not concluded in an unacceptable manner

These things are the real-life forms of the security mindset, which usually not
the main angle of interest that has driven a programmer to build his
application.  Applications usually scratch a concrete itch, a desire experienced
by a user.  Security, on the other hand, is invisible when done well, an
obstruction when it is done badly, sufficiently complex to make a good trade-off
the work of specialists.

That is what the TLS Pool wants to save application programmers from.  And
successfully — given that a TLS Pool is up and running and a developer knows his
application, it often takes as little as **one hour to add TLS** through the TLS
Pool!

Have a look at the [archdsn-usrif-id-visible.html](Application Interface)
for a bit more detail on the limited responsibilities that remain for an
application to incorporate TLS through the TLS Pool.
The things that remain to be done by the application programmer are:

-   Decide when a connection should switch to TLS

-   Setup a `tlsdata` structure with suitable flagging and identities

-   Communicate that to the TLS Pool as part of the `tlspool_starttls(3)` call

-   Wait for the TLS Pool to complete

-   Harvest the (local and) remote identities and process them as desired

Your application should usually discard any state built up before it switches to
TLS; any such preceding information is not obtained in a reliable manner, and
decisions should usually not be based on it.

When your application has the habit of asking for usernames and passwords, or
follow another method for authentication such as SASL, it is possible to skip
that step and instead ask the TLS Pool to supply identities.  But if it is
inconvenient to your users to supply credentials over TLS (because they are not
using the TLS Pool on their end?) it is better to continue your old mechanism,
and simply use TLS to wrap authentication methods that are insecure without TLS.
It is an old-fashioned method of authentication, but certainly possible.

You may want to read the [authorisation](prog-sasl.html) section for a better
idea of using any user identities passed under the TLS cloak; it can be used to
support a highly flexible mechanism that we intend to introduce along with the
[hosting split](http://internetwide.org/blog/2014/11/19/back-to-hosting.html)
into identity providers and (specialised) service providers.
