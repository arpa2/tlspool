Setup: Preparing PKCS \#11
==========================

>   *The setup of PKCS \#11 is a bit daunting when done the first time. This is
>   mostly due to the new concepts that this powerful tool offers. Once this
>   stage is passed, it provides a lot of control over the management of one's
>   crown jewels — or, more accurately, one's private keys.*

When a switch to the TLS Pool counts as a paradigm shift, then PKCS \#11 is
perhaps the biggest change for most. Instead of storing keys in plain sight on a
file system, we suddenly get a mechanism that allows us to do what we have
always felt to be right; namely, to store the keys under protective cover, not
available to the casual visitor. This is such a useful concept that the TLS Pool
relies on it for all its secret storage.

**Choosing an implementation** is the first step in setting up PKCS \#11. If you
are held to a particular brand of USB token or HSM, then this choice will
already have been made for you. In all other cases, we advise you to use
[SoftHSMv2](https://github.com/opendnssec/SoftHSMv2), at least initially. This
software is well-designed, mature and rock-solid; in addition it is
well-maintained. The origin of the SoftHSM was with the
[OpenDNSSEC](https://github.com/opendnssec/opendnssec) project, but it has since
matured into a standalone project that aims to be an “as complete as can be”
implementation of PKCS \#11.

In what follows, we will assume that you have chosen to use SoftHSMv2 underneath
the TLS Pool; if you are using another product, your approach may be somewhat
different, and you may have to refer to your vendor’s documentation for more
accurate details.

The instructions for setting up SoftHSMv2 are [detailed in the
package](https://github.com/opendnssec/SoftHSMv2/blob/develop/README.md) and
should be followed. When initialising a new token with `softhsmv2 --init-token`,
you should choose a label that will also be found in the TLS Pool configuration
file; the default configuration mentions a `pkcs11_token` whose `token` field
should match the `--label` setting.

When accessing objects concealed by SoftHSMv2, the TLS Pool will have the
`daemon_user` and `deamon_group` to determine its access to the concealed data.
If this diverts from the user and/or group that created the token instance, then
it may be necessary to correct the initialised token manually.

**Configuring the TLS Pool** is done by setting the following variables in the
configuration file, usually `/etc/tlspool.conf`:

-   `pkcs11_path` is the path to where the PKCS \#11 library is installed

-   `pkcs11_token` describes the token that you created as a [pkcs11:
    URI](https://tools.ietf.org/html/rfc7512)

-   `pkcs11_pin` is optional; you can use it to set a fixed PIN for PKCS \#11 to
    avoid asking the user; this is common on server platforms; note that
    software implementations of PKCS \#11 may only have the PIN to encrypt the
    secrets from prying eyes

 
