PIN entry Tool
==============

>   *To access PKCS \#11, the TLS Pool must supply a PIN. This should be either
>   configured, or supplied by the user, or otherwise the conclusion must be
>   that no local credentials are within reach of the TLS Pool.*

The configuration variable `pkcs11_pin` sets the PIN code to access the PKCS
\#11 repository defined with `pkcs11_path` and `pkcs11_token`. Once the
`pkcs11_pin` is removed from the configuration file (or commented out), the TLS
Pool knows that it must ask the user.

Doing this is done over the call `tlspool_pin_service(3)` call of `libtlspool`.
Any program can use this call, although a few security precautions apply.

Security precautions
--------------------

One chief advatage of using the TLS Pool and not a browser to access your
credentials is that a separate program causes the popup; separate from the
platform that is good at hosting user interactions for arbitrary remote sources
— certainly given that key strokes may be tapped by JavaScript applications.  A
separate, desktop-bound interaction is much more difficult to tackle.

But even on a desktop, we need to be careful.  The registration for PIN service
will only succeed under a number of conditions:

-   only one program can register at a time, presenting an intended response
    timeout

-   to stay registered, a program must keep its connection to the TLS Pool

-   to stay registered, a program should respond within that timeout

These rules ensure that the desktop program can blurt out loudly when it has
been denied access, which is a hint that something else registered.  A good
desktop program would also show up in a standard place, and reveal clearly that
a popup for PIN entry belongs to it.

Cut-and-dry text mode PIN entry
-------------------------------

>   `Usage: tlspool-pinentry-textual`

A minimalistic implementation of PIN entry is supplied with the TLS Pool, as
`tlspool-pinentry-textual`.  It runs on a command shell which it occupies, and
on which any requests for a PIN by the TLS Pool will be shown.

Graphical User Interface
------------------------

A dedicated project for PIN entry for the TLS Pool is provided in
[tlspool-gui](http://github.com/amarsman/tlspool-gui), where it is paired with
[local identity selection](tool-lidsel.html).
