TLS Pool Validation Policy
==========================

>   *How should we validate remote identities? What should we offer to let the
>   remote validate our local identities? There are quite a few mechanisms.
>   We’ll enable setting up policies per remote and per local identity.*

The following techniques are available (and more will follow, judging from the
rope-pulling contest between PKIX and real-life security):

-   **Chain trust:** based on signatures up to a trusted CA.

-   **CRL validation:** lookup if a certificate number is revoked. This can be
    distributed from a central point and matches with our database-driven model.
    A certificate may also mention a CRL source.

-   **OCSP validation:** a live variation on CRL validation, although often
    tuned down by simply spooning out CRL information, but it would permit local
    overrides. OCSP references from certificates may impose leak certificate
    usage information and is not advised; OCSP stapling as part of the TLS
    protocol is being proposed to overcome that. We might consider an explicitly
    configured OCSP responder under local but central control.

-   **DANE validation:** a live add-on to the other forms of certificate
    validation, DANE lists certificates, keys or their fingerprints in DNS. Note
    that DANE could also be a data source to an OCSP responder. Note that DANE
    requires additional knowledge about transport protocols and port numbers
    that are not contained in certificates.

-   **Global Directory validation:** a live add-on to the other forms of
    certificate validation, listing certificates in LDAP. This is generally
    where a remote identity administers the desirability of trust in their
    certificates.

-   **Pinning:** the storage of a fingerprint of a certificate or key as a
    returning one for the given remote identity. There may be a limitation to
    the validity period of pinned identities, resulting from limited validity of
    the certificate received.

-   **Post Quantum:** this constrains the cipher suites to only those that hold
    up under an attack by a quantum computer.  This is a much more
    [realistic threat](http://internetwide.org/blog/2018/02/10/quantum-crypto-1.html)
    than people think, so the ARPA2 project has a plan for
    [getting over Quantum Computers](http://internetwide.org/blog/2019/02/11/quantum-crypto-2.html)
    of which the ability to enforce it in the TLS Pool is an important part.
    It makes no sense at present to enforce Post Quantum crypto, as too few
    options exist today, certainly in connections to remote servers.  The best
    course of action would be to leave the default settings, and let us change
    these settings once we are satisfied that it works sufficiently often and
    can indeed be enforced.  We will of course take care of versioning constraints
    for underlying crypto software to ensure that the new cipher suites are then
    available.  Leave the defaults for an easy ride, or at best play with them
    for a while; you will see that the results are devastating for now, but the
    conclusion should *not* be to disable these settings actively, but rather to
    remove them from the configuration file let the TLS Pool distribution care
    for it, and time the change.

-   **Forward Secrecy:** the use of a suitable cipher suite ensures that future
    reverse engineering of a private key does not make stored sessions from the
    past decipherable.

-   **Anonymising Precursor:** before embarking on an exchange of keys and
    identities, wrap a cloak of ANON-DH around the handshake; the parties will
    immediately renegotiate the actual handshake. This is called an “anonymising
    precursor” to the TLS handshake. Although it is not commonly done, it helps
    to conceal the identities on the client and server side. The only situation
    in which it might be unsafe is if either side starts sending sensitive
    information before authentication completes; also note that the client must
    undertake the renegotiation, and that the server may only ask for it. In
    real-life protocols, this is rarely if ever a problem; most protocols start
    off with a less sensitive exchange that gives the server an opportunity to
    wait for authentication to complete.

Constraint Enforcement
----------------------

It is very much a matter of personal preference what constraints should be
fulfilled when validating certificates. Moreover, it may depend on the target.
We therefore do the following:

-   We define a constraint for each local user. To combine them, DoNAI selectors
    are used. This may be used to constrain trust by this local identity in a
    remote identity; it may not apply in all situations and will often be set to
    1 (for True). It is generally useful for additional constraints.

-   We define a constraint for each remote user. To combine them, DoNAI
    selectors are used. This may be used to constrain access by those remote
    identities to any local identity.

-   **No:** We define a constraint for the client role? No, but we may store it
    without a `LID_ROLE_SERVER` flag if we insist on treating client and server
    differently.

-   **No:** We define a constraint for the server role? No, but we may store it
    without a `LID_ROLE_CLIENT` flag if we insist on treating client and server
    differently.

-   **Perhaps:** We may define a constraint for each trust root. There is no use
    of DoNAI selectors to combine them. This may be useful to constrain the
    validation of a client-signing root.

These *2 or 3 sources of constraints* for remote ID validation can all be looked
up in databases. They are combined to one expression, in such a way that they
all apply.

**NOTE:** Mention of validation expressions in multiple sources is currently
not supported; setup either in `localid.db` or `trust.db` to avoid landing
the TLS Pool in undefined territory.  See
[reported issue](https://github.com/arpa2/tlspool/issues/27).

Constraint Language
-------------------

**Note:** Not all the predicates defined below have been (completely)
implemented.  Checkout
[the issue](https://github.com/arpa2/tlspool/issues/29)
for up-to-date information.

The following constructs are supported; consider them as stack manipulation
operations:

-   `1` pushes a trivially true value onto the stack.

-   `0` pushes a trivially false value onto the stack.

-   `L` applies a given level of security settings; `l` applies another level of
    security settings. Either replaces the default security level. The
    distinction between these three levels, even their ordering, is a local
    policy setting.

-   `I` and `i` ensure that the remote peer provides an identity, and that it
    does not contradict the remote identity requested by an application.
    This will often be used by a local ID that desires to know the remote ID
    if its counterpart.  The remote identity reported back to the application
    may be enhanced with identity information from the remote certification.
    The form `I` requires that the domain and username match (where absense
    of username in both is acceptable) whereas the `i` form permits a
    remote domain identity to speak on behalf of users underneath that
    domain without certifying for the username part.

-   `F` ensures that forward secrecy is employed to protect the connection. This
    property is only ensured by `TLS_DHE_`, `TLS_ECDHE_`, `TLS_SRP_` and our own
    `TLS_KDH_` cipher suites. Note that the TLS handshake phase is mostly
    visible, including the identities exchanged; see `A` and `a` for an
    alternative that resolves that too. While `F` enforces ephemeral
    Diffie-Hellman on both ends, `f` will also accept certificate-fixed
    Diffie-Hellman public keys on one of the ends.

-   `A` enforces, and `a` attempts the use of an anonymising precursor to
    conceal the actual handshake, and any identities contained in it. Since most
    TLS stacks do not implement ANON-DH as a precursor, requiring the
    anonymising precursor is currently of limited use; it should work mostly
    when the TLS Pool is known to run remotely. Although a server can withhold
    identities when it chooses to start with ANON-DH, a client has a slight
    disadvantage; it cannot refrain from sending identities that are expected in
    the ClientHello, notably the Server Name Indication, when `a` is used, but
    it may do that when `A` is used.

-   `T` validates trust based on a trusted certificate/key list. For X.509 this
    means that a path to a root certificate is needed; for OpenPGP it means that
    the trust base needs to establish some path to the key. The outcome is
    pushed onto the stack. The variation `t` will also push a positive outcome
    for self-signed certificates, thus ensuring through X.509 mechanisms that
    the certificate as a whole was issued by the private key owner; it is
    uncommon to trust `t` without other validation mechanisms like the ones
    described under `D`, `G` and `P`.

-   `D` and `d` verify through DNSSEC. For X.509, DANE’s `TLSA` records are
    investigated; for OpenPGP, `CERT` records are considered. The variation `D`
    requires presence of the information, while `d` will also accept verifiable
    denial of the information or DNSSEC opt-out for their DNS entries, meaning
    that DNSSEC assures the absense of the records. Note that DNSSEC entries are
    only advised for hosts; for individual reasons, the Global Directory is
    preferred for reasons of privacy and accurate definitions.

-   `R` verifies through lists of certificate revocations; for X.509 this means
    that CRLs are investigated; for OpenPGP it means the same as `G`. The
    variation `r` also accepts confirmed absense of a CRL for X.509, or acts
    like `g` for OpenPGP. The outcome is pushed onto the stack.

-   `E` and `e` evaluate certificate extension expressions. Where `E` only
    requires required-critical OIDs to indeed be marked critical in the remote
    peer credential, `e` will also accept those in the peer’s non-critical
    extensions. The set of OIDs to be considered are configured on a
    per-service-name basis and these are compiled into the TLS Pool; each is
    either critical (which is only enforced by `E`) or non-critical (which means
    that `E` won't require it to be a critical extension either). It is not an
    error if a non-critical extension turns up in a credential as a critical
    extension.

-   `Q` and `q` evaluate protection of cipher suites against quantum computing.
    Where `q` refers to authentication in a manner protected from quantum
    computers, and `Q` refers to such encryption strength.  The thing we need
    as fast as possible is `Q`, because current encrypted sessions can be stored
    and rewound for decryption in the (near) future.  This is more serious than
    the protection on authentication with `q`, as future quantum computers will
    not be able to authenticate with today's credentials.  For now, both options
    lead to flat-out failure, simply because the guarantees cannot be given.
    You should not learn that they cannot be used however; just be aware that
    you should always leave other options in your expressions.  Once most or
    all people have evolved to post quantum crypto you can remove the other
    options, if you decide then that they are wanting or lacking.

-   `O` and `o` validate online/live information; for X.509 this means that a
    predefined OCSP central responder under local management is being contacted;
    for OpenPGP `O` means the same as `G` and `o` means the same as `g`. Where
    `O` for X.509 requires the outcome to be `good`, the outcome of `o` may also
    be `unknown`. The outcome is pushed onto the stack.

-   `G` and `g` incorporate Global Directory information; for X.509 this means
    that a directory lookup is made for the SubjectDN, assuming it ends in
    `dc=,dc=` format and otherwise interpreting a domain name from an
    `emailAddress` or a `commonName` that looks like a domain name or a
    `dnsName` alternate name; for OpenPGP it means that the key’s own revocation
    information is verified in a key's directory entry. Where `G` requires the
    presence of a certificate in the Global Directory, `g` will also accept
    verified denial of the information or DNSSEC opt-out for their DNS entries.
    The outcome is pushed onto the stack. Note that the Global Directory is
    gentler than DNSSEC entries for individual users because it is more
    accurately defined, and because more control over user privacy is possible.

-   `P` and `p` look at locally stored pinning information, and checks whether
    it resembles the current certificate; for X.509, this means looking up a
    certificate fingerprint to match a pinned identity when it has not expired
    yet; for OpenPGP, this means looking up a public key fingerprint to match a
    pinned identity when it has not expired yet. The variation `P` fails hard
    when the pinning information is absent, whereas `p` will accept it silently
    upon first encountering it when there is nothing else pinned. It depends on
    local policy whether `p` on its own is considered secure (TOFU-style) or
    should be combined with another form of authentication, such as `D`, `G` or
    `OT&`.

-   `U` requires a match of the username with the form of identification. By
    default, it is assumed that a certificate for a domain name can act on
    behalf of any user of that domain; this is usually a sensible default
    because domains should act on behalf of their users. Note that username
    mismatches are never acceptable; one user cannot act on behalf of another
    user; the default case merely permits a certificate for a domain without
    username to act on behalf of all users situated under that domain. So, in
    fact, this requirement comes down to simply adding the requirement that a
    username is present in the remote ID if it is to represent a user. TODO:
    Consider adding `u` for…? perhaps to try to find a username, but possibly
    accept a hostname only. Default behaviour with neither is then to only take
    out the host name.

-   `S` and `s` select the situation where the local TLS protocol side acts as a
    server; `S` additionally ensures that it uses a certificate marked in the
    local identity database just for server use (that is, `S` suppresses
    peer-to-peer validation and `s` permits it).

-   `C` and `c` select the situation where the local TLS protocol side acts as a
    client; `C` additionally ensures that it uses a certificate marked in the
    local identity database just for client use (that is, `C` suppresses
    peer-to-peer validation and `c` permits it).

-   `&` combines the top two stack entries through conjunction.

-   `|` combines the top two stack entries through disjunction.

-   `~` replaces the top stack item with its logical inverse.

-   `?` removes the top stack item; if it is true, it keeps the second but
    removes the third; otherwise it keeps the third but removes the second.

These operations are implemented as lazily as possible, of course. Checks may be
mentioned more than once without them actually being computed over and over
again.

The outcome of the operations is usually one of four states: `uncomputed`,
`positive`, `negative` or `absent`. At least the `positive` and `absent`
outcomes must be verifiable to stop any attacks. Note how usually the lowercase
letter stands for a weaker version of the uppercase letter; that is, uppercase
=\> lowercase. Indeed, the various checks may learn from each other.

**Syntax.** A correct expression is one that leaves a single expression on the
stack. In addition, it is not permitted to remove undefined values from the
stack. A simple check can validate these properties.

**Bit-code semantics.** *Not true, we need two levels of NAND:* A compact
storage form is a sequence of bit fields. The sequence expresses the top-level
`&` and within the bit field is the `|` with variations with and without `~` per
bit; each bit represents one of the letters/digits above. This does not answer
to the `?` operator, or otherwise it does it indirectly. Such structures can be
evaluated efficiently, because it can quickly be determined what the minimum
effort is. The value `1` can be most compactly represented in an empty list.  
*Additional idea:* x?y:z == xy&x\~z&\|yz&\| — the yz& case being an unexpected
shortcut :-D

**Combining constraints.** As stated, the local and remote ID as well as
(perhaps) a trust root may give rise to constraints. Each of these must
independently pass the syntax check. Note that both check the remote ID
validity. The two are run in sequence and then `&` is run to combine them. More
constraints may be added, each followed by an `&` operation. Or, in terms of the
semantics, the sequences are (considered) concatenated. Many local ID
expressions will simply be `1` to avoid running any logic.

**Example.** A typical configuration for “proper” certificate verification would
be

-   Require a chain of trust

-   Validate CRL or OCSP

-   Validate DANE or Global Directory

This would be formulated as `TCO|DG|&&` or, equivalently, `TCO|&DG|&`

**Example.** Another typical configuration could be a reasonably reliable
“self-signed” format:

-   Do not require a chain of trust

-   Validate pinning or DANE or Global Directory

This would be formulated as `PDG||` or, equivalently, `PD|G|`

Parameter Settings
------------------

Some of the validation schemes may require parameters. These parameters are set
separately, because they may not be proper at the places where the constraint
language is stored.

-   **X.509 Root CAs.** These are used as trust anchors when performing X.509
    certificate chain validation. It is stored in the trust database.

-   **OpenPGP Trusted Keys.** These are considered trusted signers. It should
    currently be setup to support no intermediate keys, so there need not be Web
    of Trust evaluations. This key list is stored in the trust database.

-   **OCSP Responder.** This points to an OCSP responder, usually under local
    control, together with the public key that it uses to sign responses. It is
    stored in the trust database.

-   **Local Directory.** This references an LDAP repository that enhances,
    filters and generally overlays the Global Directory to form a local access
    path to it; it may be used for local adaptions to what is published to the
    Internet, or it may be used to make references from an `o=,c=` LDAP root to
    a `dc=,dc` alias. This is stored in the trust database.

-   **Extension OIDs.** These are set per service type. They are stored in the
    trust database. The options `E` and `e` look at these values. Each extension
    OID is set to be either critical or non-critical. The textual format is
    `OID` for non-critical, and `OID!` for critical extensions; values are not
    defined for now, but may add something like `=...` to the format in future
    versions. Verifications can be composed with `&` and `|` postfix operators;
    there is no negation or other logic complexity. The database may use a
    binary format based on the RFC 5280 definition of `Extension`, which
    includes a value (to be set empty) and a `CRITICAL` flag; the logic
    constructs will be captured by placing `&` compositions in a `SEQUENCE` and
    `|` compositions in a `SET`, using De Morgan to limit everything to two
    levels.

-   **Key Sizes.** These are defined for each permitted algorithm, and used to
    select appropriate cipher suites. They are stored in the trust database. We
    permit two security levels, e.g. reflected in an `L` and `l` command, and
    set values for each separately; in addition, there is a nothing-said default
    security level. It is up to the local policy settings what the
    interpretation of the default, `l` and `L` levels are. Note that some
    algorithms may be banned from one security level only.

Anticipated Use Cases
---------------------

Below, we write `=>` for database mappings, `key => value` and we use [DoNAI
selectors](<http://donai.arpa2.net/selector.html>) as keys because we match
against a remote identity in [DoNAI](<http://donai.arpa2.net>) form.

It is expected that a public service, such as a website, will set its default
formula for local identities straightforwardly to

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 .                      => 1
@.                      => 1
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

but override it for local sites that require certificate login to something
along the lines of

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
my.example.com          => TCO|DH|&&
  @example.com          => PDG||
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

On the other hand, a typical client's default setting for remote ID will be more
stringent, for instance

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 .                      => TCO|DH|&&
@.                      => TCO|DH|&&
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

and in this case overrides may actually be lenient on specially selected
remotes, as in

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 befriended.example.org => PDG||
@befriended.example.org => PDG||
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Which will let friends in on grounds of pinned identities and a few methods to
bootstrap it under their own control. We’re only trusting that on top of basic
certificate validity for the more general case of remote identities. Note that
no effort is made to validate the certificate’s (self-)signature. Had we wanted
that, we could have added `t&` at the ends of the formulæ given.

Finally, a wilder example; a server might employ a certificate with a trivial
RSA signature (for example: modulus `0x01` always gives signature value `0x00`)
but have the total certificate protected through one of the other means (DANE,
Global Directory, Pinning) and it might mention a fixed Diffie-Hellman public
key. The server side cannot participate in forward secrecy, but the client may
still toss in enough random material to obtain a session key with the property.
Such a wild configuration might be approved with

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
wild-demo.example.org   => PDG||F&
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This example is actually more stringent than the average self-signed certificate
proposal; the additional requirement of forward secrecy might of course be
applied to those as well; the only thing “wild” about this example is the form
of the certificate, where the signature is ignored and thus setup with a really
trivial value.

Note that clients and servers vary in which of the identities is present. A
server may welcome anything, which is reflected by the default assumption that
the local identity is not constrained, but the remote identity is if it exists.

Servers acting after-the-fact
-----------------------------

TLS being what it is, servers do not know the client identity before they choose
a cipher suite; the only thing they may know is their own local identity. This
means that, different from the examples above, a server may need to set more
stringent validation expressions when they are known to act as a server. Note
that the settings will be reloaded once the client identity is known, and they
will be applied; but at that time, a server may be stuck to a choice that it
made in an earlier phase, and that it rejects in the later phase.

To support a solution in this area, the commands `S` and `s` have been created,
together with their mirror images `C` and `c`. These can be used to be more
demanding on servers, for example for the local default names.

Interactive configuration tools, such as web interfaces, should perhaps warn
when this kind of problem is likely to occur. They can do this by comparing
server settings at different levels of abstraction — such as a concrete name and
the default name.
