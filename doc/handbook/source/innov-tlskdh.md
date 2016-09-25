Kerberos through TLS-KDH
========================

>   *The most exciting enhancement that is introduced through the TLS Pool is
>   its support of Kerberos, which it always does in unison with Perfect Forward
>   Secrecy.  This modified TLS protocol is not only much more efficient than a
>   classical X.509-based security model, it also resolves many issues that have
>   historically grown around the X.509 system, leads to improved user
>   experience and is more to the point about its security guarantees.*

The normal flow of a full-blown TLS handshake, where both ends supply a
`Certificate`, is as follows:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      Client                                               Server

      ClientHello                  -------->
                                                      ServerHello
                                                      Certificate
                                                ServerKeyExchange
                                               CertificateRequest
                                   <--------      ServerHelloDone
      Certificate
      ClientKeyExchange
      CertificateVerify
      [ChangeCipherSpec]
      Finished                     -------->
                                               [ChangeCipherSpec]
                                   <--------             Finished
      Application Data             <------->     Application Data
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is certainly not always the case that the client authenticates; most secure
web servers will relay pages to anyone, and authenticate themselves to the
client but not require to validate the client’s identity.

Still, there are situations where the client identity is of use — a
`personalised` service, possibly with authorisations for certain functions based
on a validated client identity.

In either case, the customary form for the `Certificate` messages is that of an
X.509 Certificate.  Alternatives are possible, notably OpenPGP Public Keys and
even raw public keys.

For the [InternetWide
Architecture](http://internetwide.org/blog/2016/06/24/iwo-phases.html) however,
we have selected the Kerberos infrastructure as the principal cornerstone of
identity.  This is a very common choice made in many corporate infrastructures
as well — except that then it is used internally.  What we aim to do is [connect
realms all over the Internet](http://realm-xover.arpa2.net/kerberos.html),
[facilitate
authorisation](http://internetwide.org/blog/2015/04/25/id-5-ksaml.html), allow
people a
[bring-your-own-identity](http://internetwide.org/blog/2015/04/22/id-2-byoid.html)
service level but with privacy protection through [pseudonyms, aliases, roles
and groups](http://internetwide.org/blog/2015/04/23/id-3-idforms.html).  yeah,
that’s quite a bit, but we found the places to integrate this with Kerberos —
it’s mostly a matter of making it happen.

Now let’s look at HTTPS security.  Its current integration with Kerberos is
disastrous, to say it politely.  The best efforts in this direction are all
known to be flawed and barely secure.  The practices behind their deployment may
be even worse.  This is in sharp contrast with the usefulness of having a good
HTTPS setup based on a company’s single-signon infrastructure.  In fact, the
poor systems of today are usually only tolerated because there is no alternative
and people do like to have their single-signon enacted for the web.

In contrast with these current practices, what we do with TLS-KDH is to
integrate Kerberos in a cryptographically solid manner with TLS.  We use a
Kerberos ticket as the client's `Certificate` which, in line with the way
Kerberos works, also authenticates the server without needing it to send one.
The server may however still send a classical X.509 Certificate, which may prove
useful if the client opts out of Kerberos (choosing to not be authenticated).
The `ServerKeyExchange` and `ClientKeyExchange` are filled with the proper
fillings to ensure Perfect Forward Secrecy, a property that avoids tapping even
when keys are known — a great asset in general, and basically a must with
Kerberos.

HTTPS can directly benefit from this, and may refer to the TLS layer to learn
about client identities, if it cares.  For mail and chat servers, and basically
anything else, the same mechanism can be used (they might use `SASL EXTERNAL` to
implement authorisation).

The mechanism described here is surprisingly more efficient than that of X.509
Certificate validation.  TLS-KDH [research suggests 5000-fold
improvements](javascript:alert("tom thesis... link?"))  of the authentication
effort!  This can be quite helpful in light of the growing desire to “encrypt
everything”.  Much of the advantage lies in the use of symmetric crypto by
Kerberos, but the infrastructure is also simpler: instead of long-lived X.509
Certificates that are founded on a feeble email check and which may have to be
withdrawn later, a Kerberos ticket is so short-lived that it can be used without
retraction infrastructure.  The next day, a new ticket will be acquired and used
because yesterday’s has stopped to be usable.

Combine the immense potential that the TLS-KDH mechanism offers with the idea
that Kerberos can be taken out of companies to work on the Internet as a whole —
with that, and the much faster response times compared to X.509, a highly
pragmatic mechanism has been created for a future, secure Internet.

TLS-KDH should rank high for its innovative empowerment, but in the end it is
just one of the options when using the TLS Pool — it is never enforced.  It is
helpful however, that the TLS Pool speaks with applications in terms of
identities, not certificates.  This means that the application does not need to
be aware of the mechanism that brought it the authenticated identities that it
can act on — the TLS Pool handles it all.

Given the high efficiency and relative simplicity of making a solid
implementation of TLS-KDH, a special profile has been created that includes
*just* TLS-KDH.  This may be useful for constrained environments, such as
embedded systems.
