# SteamWorks Pulley Scripts for TLS Pool

> *Pulley is the part of SteamWorks that digs up information from LDAP, stays
> subscribed to it for updates, mixes and matches the information found with
> an expressiveness akin to SQL, and finally delivers it in a local format.
> This backend to Pulley is meant to deliver information to the TLS Pool
> databases.*


## Output drivers

The place where this plugins gets to work is as a so-called *output driver*
in the Pulley Script language.  It is parameterised to receive certain
parameters, and maps those to the databases.

The output driver is for `disclose.db`, which is parameterised with

    ... -> tlspool (config="../etc/tlspool.conf", type="disclose", args="...")

The two parameters provided are the configuration file for the TLS Pool
and the type of database.  Multiple instances of this output driver
are possible, at the very least to support multiple databases.

There is no requirement to cover all the three database types underneath
the TLS Pool (they are `disclose`, `localid` and `trust`) as local
mechanisms may be used instead.

It is in fact possible to have multiple instances of the same database
type; in that case, an additional `subkey` argument may be helpful to
keep them separated.  See the descriptions per database below.

The code for the output driver support is found
[here](../pulleyback).


## Disclosure database

The information sent to the output driver for a `disclose` type database
is simply a pair of remote and
local identity variables (noted as `rid` and `lid` respectively), as in:

    lid,rid -> tlspool (..., type="disclose",args="localid,remoteid")

or, alternatively,

    rid,lid -> tlspool (..., type="disclose",args="remoteid,localid")

Note how the `args` determine how the arguments are interpreted.  Only the
given two forms are possible for the `disclose` type backend.  (Future
extensions may however incorporate validation expressions as well.)

There is no obligation to service this mapping from LDAP though; a rollout
may prefer to use a GUI element to do this instead.  It may even both be
done; the Pulley backend is aware that this can lead to conflicts,
and will silently accept when an attempted removal was already done over
the GUI; likewise for additions.  Note that this may not be the gentlest
situation for end user experience though; if the LDAP version of the data
is flapping it would consistently overwrite the user-set data.


## Local identity database

This database is marked by type `localid` but beyond that it
falls apart in a number of perspectives, which could be
seen as a subkey mechanism.  Therefore, provide a few extra parameters
to the output driver:

    .... -> tlspool (..., args=..., subtype="x509,client")

The `args` indicates how arguments supplied to the output driver are
interpreted.  Possible values are:

  * `localid` for the local identity being described, which must be present;
  * `pkcs11` for the PKCS #11 URI of a private key, which must be present for any but the `valexp` subtype;
  * `cred` for the public credential identifying the local identity, which must be present for any but the `valexp` subtype;
  * `valexp` for the validation expression, which must be present for the `valexp` subtype;
  * `credtype` for dynamically supplied credential types other than `valexp`;
  * `role` for dynamically supplied roles.

The `subtype` consists of a number of information bits:

  * credential type selection from `x509` for X.509 certificate entries,
    or `openpgp` for OpenPGP entries;
    alternatively, `valexp` for validation expression entries; future
    extensions will probably also recognise `openssh`, `krb5`, `srp11`;
    this must not be provided when `credtype` is in `args`;
  * role selection from `client` or `server` to indicate the role to which
    the setting applies, or `peer` if it applies to both;
    this must not be provided when `role` is in `args`.
  * an additional flags that can be requested is `chained`.

The dynamic form is provided to permit additional arguments to be supplied
to the Pulley backend in a dynamic form.  This is why it is either/or
with the static values in the `subtype` argument.

The dynamic form is primarily useful for LDAP-supplied data.  The values
for `credtype` match the singular attribute type `tlsPoolCredentialType`
and the values for `role` match the singular attribute type
`tlsPoolSupportedRole` -- and that is not a coincidence!

The arguments to the Pulley backend for the TLS Pool could be:

    lid,p11uri,cred -> tlspool (...,args="localid,pkcs11,cred")

As explained before, the presence of `role` and `credtype` arguments
can lead to additional arguments from a dynamic source, for instance

    lid,p11uri,cred,role -> tlspool (...,args="localid,pkcs11,cred,role")

Note that in the LDAP scheme, the
`valexp` value is usually supplied in a different manner, as it is not
part of the `tlsPoolCredentialType` and will not dynamically resolve
to the argument for the `credtype` parameter.  This matches nicely with the
auxiliary object class `tlsPoolValidationRequirements` for validation
expressions, which may be applied independently on top of a
`tlsPoolLocalUserCredential` structural object class.

In the local identity database, validation expressions "abuse" the
PKCS #11 URI field to hold the
validation expression, and there is never a public credential, so its
format will usually be simply:

    lid,valexp -> tlspool (...,args="localid,valexp")

or with the `role` argument made dynamic, because it can be combined
meaningfully:

    lid,valexp,role -> tlspool (...,args="localid,valexp,role")


## Trust database

**Note:** See the current TLS Pool implementation details for the
progress on trust database settings.  The model for LDAP moves independently
and may be more complete than what is acceptable to the TLS Pool backend.

The configuration of the `trust` backend type has a subtype in a similar
fashion to that of the `localid` type:

    .... -> tlspool (..., args=..., subtype="authority,x509,client")

The `args` parameter defines how arguments to the output driver will
be interpreted:

  * `cred` indicates the public credential being dealt with;
  * `role` indicates dynamically whether the trust is for `client`, `server` or both (`peer`) credentials
  * `valexp` indicates a validation expression supplied dynamically,
    when there is no parameter `valexp` configuring the output driver
    to a fixed one.

The `subtype` consists of a number of information bits:

  * `x509` for X.509 certificate entries, or `openpgp` for OpenPGP entries;
    alternatively, `valexp` for validation expression entries; future
    extensions may also recognise `openssh`, `krb5`, `srp11`;
  * `client` or `server` to indicate a static role to which the setting
    applies, or `peer` if it applies to both;
  * `authority` to indicate a trusted CA certificate (root or intermediate);
    more entry types will follow, for instance `revocation` and `pinning`
    are considered to be useful future additions.

In addition, a static `valexp` may be supplied, which will then apply
to all the productions from the output driver.  The simplest form to
facilitate the required validation expression for trust database entries
is:

    .... -> tlspool (...,valexp="1")

The arguments to a trust output driver, using a dynamic validation expression
obtained from a source like LDAP, could be:

    valexp,cred -> tlspool (...,args="valexp,cred")

Here, `valexp` provides a validation expression and `cred` provides a
public credential for the trusted entry.

For `authority,x509` subtypes, the credential is assumed to hold a
subject key identifier, which is then used as its index into the trust
database.  When absent, the subject key identifier is computed as
described in Section 4.2.1.2 of RFC 5280, using `(1)` the full SHA1 form.

For `authority,openpgp` subtypes, the credential's 64-bit key ID is
derived and used as the index into the trust database.


## Example Pulley Script

The following is a maximally dynamic script that could be used to pull
information from the LDAP scheme for the TLS Pool, and placing it in
the disclosure database:

    # SteamWorks Pulley Script: LDAP --> TLS Pool disclose.db
    #
    # From: Rick van Rein <rick@openfortress.nl>

    # Pull information from the disclose root
    TODO

    # Find group members that form lid/rid combinatiosn
    TODO

    # Supply each lid/rid pair to the disclose.db
    lid,rid -> tlspool (config="/etc/tlspool.conf", type="disclose", args="localid,remoteid")


The following is a maximally dynamic script that could be used to pull
information from the LDAP scheme for the TLS Pool, and placing it in
the local identity database:

    TODO


The following is a maximally dynamic script that could be used to pull
information from the LDAP scheme for the TLS Pool, and placing it in
the trust database:

    # SteamWorks Pulley Script: LDAP --> TLS Pool trust.db
    #
    # From: Rick van Rein <rick@openfortress.nl>
    
    ### X.509 trust ###
    
    # Generate <x509ca,x509cadn> as a potential root certificate
    ObjectClass: "pkiUser" + UserCertificate: x509ca, @cadn, Ou="Trust Contestors" <- world
    
    # Generate <x509anchordn,x509valexp,x509role> to describe a trusted CA
    ObjectClass: "tlsPoolTrustedIssuer" + TlsPoolCredentialType: "x509" + TlsPoolTrustAnchor: x509anchordn + TlsPoolValidationExpression: x509valexp + TlsPoolSupportedRole: x509role, Cn=_, Ou="Our Foundation of Trust" <- world
    
    # Trim down to x509ca certificates that are trusted
    (x509cadn == x509anchordn)
    
    # Send the found results to the TLS Pool backend
    x509ca,x509valexp,x509role -> tlspool (config="../etc/tlspool.conf", type="trust", args="cred,valexp,role", subtype="authority,x509")
    
    ### PGP trust ###
    
    # Generate <pgpkey,pgpkeydn> as a potential PGP direct signer key
    ObjectClass: "pgpKeyInfo" + PgpKey: pgpkey, @pgpkeydn, Ou="Trust Contestors" <- world
    
    # Generate <pgpanchordn,pgpvalexp,pgprole> to describe a trusted signer
    ObjectClass: "tlsPoolTrustedIssuer" + TlsPoolCredentialType: "pgp" + TlsPoolTrustAnchor: pgpanchordn + TlsPoolValidationExpression: pgpvalexp + TlsPoolSupportedRole: pgprole, Cn=_, Ou="Our Foundation of Trust" <- world
    
    # Trim down to pgpkeys that are trusted
    (pgpkeydn == pgpanchordn)
    
    # Send the found results to the TLS Pool backend
    pgpkey,pgpvalexp,pgprole -> tlspool (config="../etc/tlspool.conf", type="trust", args="cred,valexp,role", subtype="authority,openpgp")
