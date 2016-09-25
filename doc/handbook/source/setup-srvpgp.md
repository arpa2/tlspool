Setup: Server with OpenPGP Public Keys
======================================

>   *As an alternative to X.509 certificates, it is also possible to use OpenPGP
>   public keys to authenticate a server.  An advantage of this is not having to
>   deal with external authorities.  A problem is that something must be done to
>   authenticate the keys in use, but the TLS Pool has a simple answer to that.*

The support for OpenPGP is a clear example of what we believe is good for a
security platform, namely to setup a number of mechanisms and be prepared to
switch off ones that have shown to be unreliable.  This is why we put an effort
in having multiple mechanisms available, and why we are proponents of using
OpenPGP Public Keys next to X.509 Certificates.

**TODO:** This is not completely implemented at this time; specifically, the
validation of the OpenPGP public key through the LDAP Global Directory has not
been finished yet.

Generally, the process of creating an OpenPGP key is a single step, started by
firing an interactive session with a tool such as GnuPG.  But for the TLS Pool,
the use of PKCS \#11 makes the solution a bit more complex.

As with X.509, we **create a private key** in the PKCS \#11 store using

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
P11LIB=`tlspool-configvar -c /etc/tlspool.conf pkcs11_path`
P11URI=`tlspool-configvar -c /etc/tlspool.conf pkcs11_token`
p11tool --provider "$P11LIB" --login --generate-rsa --bits 2048 --label=Label --id=30303032 --outfile=/dev/null "$P11URI"
OBJURI="$P11URI;id=%30%30%30%32;label=Label;type=private"
echo "PKCS #11 Object URI: $OBJURI"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Next, we **construct a public key** from the private key but, lacking tooling
for that in most open source projects, we have created our own and called it
`pgp11_genkey`.  We use it as follows:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
pgp11_genkey "$P11LIB" "$OBJURI" "<www.example.com>" key.gpg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The output file in `key.gpg` now holds a public key.  **Do this only once:** the
fingerprint of the key depends on the time stamp at which we self-signed
`key.gpg` and if you were to repeat it later on you would end up with another
fingerprint, even if the public and private keys are the same!  So if it could
be of use to you in the future, be sure to copy `key.gpg` to safe storage before
proceeding.

We now have a combination of a private key URI and a public key and so we can
proceed to importing it into the TLS Pool, much like we did for X.509:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set_localid /etc/tlspool.conf www.example.com OpenPGP,server "$OBJURI" key.gpg
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removal works the same; just leave out the `pkcs11:` URI and the `key.gpg`
filename.  As with X.509, there will be no need to restart the TLS Pool after
updates to the `localid.db` because the TLS Pool will see the change next time
the identity is needed.
