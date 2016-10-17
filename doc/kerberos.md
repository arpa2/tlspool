# Kerberos and the TLS Pool

> *We have started to integrate Kerberos into the TLS Pool, but for now it is
> a bit crude.  We haven't yet established how to distribute responsibilities.*

The integration of
[TLS-KDH](https://tools.ietf.org/html/draft-vanrein-tls-kdh)
into the TLS Pool is a major contribution towards a secure, yet fast
Internet.  It combines fluently with our sub-projects on
[realm crossover](http://realm-xover.arpa2.net/kerberos.html)
and
[bring your own identity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html)
combined with
[authorisation](http://internetwide.org/blog/2015/04/25/id-5-ksaml.html)
for privacy in spite of
[hosting-market specialisation](http://internetwide.org/blog/2014/11/19/back-to-hosting.html).
Yeah, we have a
[pretty big plan](http://internetwide.org/blog/2016/06/24/iwo-phases.html)
on where to take the Internet!

The matter with Kerberos is mainly who should hold the ticket cache being
used.  There are two basic possibilities, it could be made internal to the
TLS Pool, or it could be externally provided over a new API.

When we choose to use a new API for Kerberos it
may or may not integrate with the user's desktop.  Very often, desktops
can hold Kerberos credentials or they can easily have them added, sometimes
even united with the desktop login (and screensaver-protected) session.
Moreover, the desktop is the place where the user might switch the primary
identity being used.

The alternative is to let the TLS Pool hold the Kerberos credentials for
a user, and that would allow the integration of PKCS #11 in the sign-up
process, which is specifically interesting in relation to PKINIT.

The matters that help to decide on this are:

  * The desktop location would require the
    [new socket protocol](socketprotocol.rst)
    because Kerberos tickets can grow larger than what we have fixed-allocated.
  * Whether PKINIT is a good idea depends on what is the "security foundation";
    is it Kerberos, or is it PKCS #11 -- because each can cause the other to
    be created.  We should even ask ourselves if the TLS Pool should make this
    choice, or be supportive to both.  Desktops and mobile stations may need
    to make different choices, for example.

At present, the crude implementation of Kerberos involves using the PIN
request to obtain a Kerberos password; this means that it must be entered
manually *or* that the Kerberos password should match the configuration
file's fixed PIN setting `pkcs11_pin`.  Clearly, the choice of layering
one mechanism on top of the other has not yet been forced and so we are
dealing with this kludge for now.

