Setting up the TLS Pool
=======================

>   *Until the TLS Pool is well-integrated into distributions, you will have to
>   install it by hand. This means that you will be subjected to the full
>   procedure, without short cuts. The TLS Pool is a paradigm shift when it
>   comes to dealing with secure connections, so the work unfolds in a number of
>   steps to take.*

In the following, we will go through a number of steps:

-   [Prepare the System](setup-system.html) for the upcoming install of the TLS Pool

-   [Prepare PKCS \#11](setup-pkcs11.html) for storage of private and secret keys

-   [Setup databases](setup-databases.html) for storage of dynamic data

-   [Setup server certificates](setup-srvcert.html) on the server end, if needed

-   [Setup server PGP keys](setup-srvcert.html) on the server end, if needed

-   [Setup client certificates](setup-clicert.html) on the client end, if needed

-   [Setup client PGP keys](setup-clicert.html) on the client end, if needed

-   [Setup Trust Anchors](setup-trust.html) on either end

-   [Setup the TLS Pool daemon](setup-daemon.html) by configuring and running it

-   [Setup dynamic reconfiguration](setup-pulleyback.html) through a PulleyBack
    script

The process will be a bit complex at first, especially when it is run for the
first time. Rest assured that the concepts are perhaps new, but in no way a
waste of your time.

Especially the extra work to go through PKCS \#11 is new to many and may feel
like ballast, but it yields so much flexibility and control over security levels
and even distribution matters that the learning experience can usually be
considered quality time — at least in retrospect.

**Testdata** is a
[directory](https://github.com/arpa2/tlspool/tree/master/testdata) in the TLS
Pool [distributation](https://github.com/arpa2/tlspool) that automates much of
this work already, but it is geared at giving developers a head start, but it is
not meant for users. You may find it useful to inspect the
[Makefile](https://github.com/arpa2/tlspool/blob/master/testdata/Makefile) that
creates many credentials and databases and so on automatically.

 
