Architecture and Design of the TLS Pool
=======================================

>   *The TLS Pool makes a few surprising choices. They may take a while to get
>   used to, but their resulting separation of concerns is so useful that it may
>   feel like the only sane way of doing this.*

The TLS Pool is not the same to everyone. There are a number of interfaces:

-   The [application interface](archdsn-applif-sock-id.html) deals with sockets and
    identities.  This differs from products such as `mod_ssl` in Apache,
    where entire certificates are shown to applications, and left to them to
    decode.  At the same time, this brings flexibility in handling certificates,
    and it restricts the freedom to use another authentication mechanism than
    those certificates.  The TLS Pool generalises this by exchanging a generic
    form of identity.

-   The [user interface](archdsn-usrif-id-visible.html) speaks with the user (usually
    through a GUI) in terms of identity selection, which remote peers may see
    it, and password entry to the PKCS \#11 backend.

-   The [configuration interface](archdsn-cfgif-cred-trust.html) works through databases that
    store knowledge about trust (in remote validation) and credentials (to prove
    validity towards a remote).

The following subsections detail these mechanisms.
