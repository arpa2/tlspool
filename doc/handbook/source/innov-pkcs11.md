Reliance on PKCS \#11
=====================

>   *When you have reached this point in the TLS Pool Handbook, you may have
>   seen the term PKCS \#11 so often that you have stopped to think of it as
>   innovative.  Despite that, the choice to build the TLS Pool around PKCS \#11
>   and to support integration with external components for management of local
>   credentials is highly innovative.  Not only that, it solves real problems
>   felt by real security administrators.*

PKCS \#11 is useful for a number of reasons:

-   It separates secret or private keys from the TLS protocol logic.

-   It enables the administrator a range of choices in security levels.

-   It may work on a remote key storage device.

-   It may facilitate cryptographic speed-up.

-   It helps to lift reliance on hardware security — or virtual host security.

In client environments, it is somewhat common to see PKCS \#11 implemented.  The
TLS Pool is a first innovator to also pull it into the server environment.
