Setup: Server with X.509 Certificates
=====================================

>   *The most-used form of server authentication uses X.509 certificates, also
>   known as PKIX certificates.  This section explains how to set them up for
>   the TLS Pool.*

They bind a public key with an algorithm such as RSA or ECDSA to an identity,
which includes the web server name.  The binding is confirmed by a trusted third
party, or certificate authority.  This may be a paid party, or one providing
certificates for free, such as [Let’s Encrypt](https://letsencrypt.org) or
[CAcert](https://www.cacert.org).

Generally, a certificate authority will explain the hoops that you must jump
through:

1.  Generate a *private key* of a certain algorithm and size, for example 2048
    bits RSA or 256 bits ECDSA.  As a side-effect, a *public key* is usually
    derived from the private key as well.

2.  Using that, generate a *certificate request*, which incorporates the public
    key and your intended identity, notably `CN=www.example.com` and perhaps one
    or more DNS names also explicitly mentioned.  A special form is a wildcard
    certificate, such as `CN=*.example.com`, which would cover any name under
    the domain name.

3.  Then you upload only the certificate request.  The certificate authority is
    likely to scrutinise your request, strip parts that it won’t allow and
    perhaps provide alternative forms of a name, such as the domain name without
    the `www` prefix label.

4.  The certificate authority should now do some hard work to validate that you
    are the owner of the website.  In practice, a flimsy test such as the
    ability to receive email is considered sufficient to grant you a certificate
    for 1 up to 3 years.  Sarcasm intended.

5.  You now receive the certificate over email, or can download it somewhere.
    Used together with the private key that you kept to yourself, you can now
    instruct your server to secure its connections with TLS.  The way to do that
    is completely dependent on the server program, but often comes down to
    mentioning the paths of the two files somewhere in a configuration file.

This path is still the same with the TLS Pool, except that we use PKCS \#11 and
so our private keys are better protected — at least that is possible, but it
depends on the precise PKCS \#11 implementation chosen.  But even the basic
SoftHSMv2 that we advise to newcomers already encrypts the certificate with a
PIN, thereby improving over what most servers do.  Also, the design of the TLS
Pool as a separate process means that access to this file is not required from
the same server that may be running [scripts of mediocre
quality](http://internetwide.org/blog/2014/07/03/webarch-authentication.html)
and often [dubious maintenance
status](http://internetwide.org/blog/2014/07/03/webarch-scriptkiddies.html).

To **create a private key** with the TLS Pool, we need to run a tool that is
versed in PKCS \#11.  Instead of `openssl rsa` that quickly becomes cryptic when
handling PKCS \#11, we recommend using the tools that come with GnuTLS:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
P11LIB=`tlspool-configvar -c /etc/tlspool.conf pkcs11_path`
P11URI=`tlspool-configvar -c /etc/tlspool.conf pkcs11_token`
p11tool --provider "$P11LIB" --login --generate-rsa --bits 2048 --label=Label --id=30303031 --outfile=/dev/null "$P11URI"
OBJURI="$P11URI;id=%30%30%30%31;label=Label;type=private"
echo "PKCS #11 Object URI: $OBJURI"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `--id=30303031` form is a bit awkward; it represents the identity, which
often is a binary identity, in hexadecimal form, so the identity given here
would be `0001` when interpreted as ASCII.  The main use of the identity is
matches private keys to public keys and perhaps certificates.  The `--label` on
the other hand, is intended for human consumption.

Neither the `--id` nor the `--label` needs to be unique — other than for
practical purposes of finding back the one object that you are looking for, of
course.  Assuming that at least their combination is unique, the printed
`pkcs11:` URI should help to locate the generated private key in the future;
note how the hexadecimal content is percent-escaped in the URI form.

For the upcoming request, we should **write a template file** holding the
details of how we would like our certificate to look.  We will assume below that
the template is saved in `request.template`. An example can be found in the
`certtool(1)` manual page, but a short form that should work mostly is

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
organization = "Snake Oil, Ltd"
state = "Bliss"
country = US
cn = "www.example.com"
dns_name = "www.example.com"
dns_name = "example.com"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We now **create a certificate request** using the concealed private key.  For
this, we use another tool from GnuTLS:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
certtool --provider "$P11LIB" --generate-request --outfile request.pem --template=request.template
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The result in `request.pem` is what you should ship to your certificate
authority.

We now **twiddle our thumbs** until our certificate authority has done its work.
This may involves jumping through some hoops, such as clicking on a link in an
email sent to your domain administrator’s address.

Upon arrival, **save the certificate** to a file named `new.pem` — or at least,
that will be the name assumed below.  We shall also assume that you got the
textual form, as that is common.  We however, need the binary form so we need to
transform it from PEM to DER notation:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
certtool --infile new.pem --outfile new.der --outder
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We now hold a file named `new.der` that we can use to import into the TLS Pool.
And remember the `pkcs11:` URI for the object?  We saved it in `$OBJURI` when
generating the private key, as well as printed it on the output.  We will need
that too, because now we bring the signed certificate and the private key
together.

To **import the certificate and private key** as a pair into the TLS Pool, we
run the following command:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
set_localid /etc/tlspool.conf www.example.com X.509,server "$OBJURI" new.der
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The arguments on this line are:

-   A reference to the configuration file for the TLS Pool; this is used to find
    the database environment and the `localid.db` locations.  If the database
    and/or its environment have not been created yet, this tool will do it for
    us.

-   The name for which the newly imported credential can be used.  You may
    additionally want to import it without the `www` prefix label.  If you hold
    a wildcard certificate, please understand that the TLS Pool does not search
    its `localid.db` in that way; you should import each covered name
    separately.

-   The flags indicate that the type of this entry is an X.509 certificate,
    meant to be used in a server.

-   The `pkcs11:` URI and the filename of the DER file with the certificate are
    all that’s left.

Variations exist.  For instance, you might have added anything but the root
certificate to `new.der`, in the order of escalating the hierarchy.  In that
case, you should add the `chained` flag as well.  This is how non-standard
certificate authorities (those that are not in `trust.db` or another certificate
authority list on the remote end) can be supported;
[CAcert](https://www.cacert.org) is probably the best-known example of that.

After this, your done.  If you ever need to **remove the certificate**, for
example because its due date has passed, you can either overwrite it with a new
one (using the same flags) or you can rerun the command but leave out the
`pkcs11:` URI and DER file name.

You do not need to restart the TLS Pool after having modified the database; it
should pickup automatically.  This is the main reason for using databases to
configure these things.
