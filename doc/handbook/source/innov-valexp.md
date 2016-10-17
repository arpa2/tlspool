Validation Expressions
======================

>   *TLS implementations have various levels at which they can scrutinise the
>   security of a remote peer. Mostly, the variations in these levels is fixated
>   in software. The TLS Pool loosens this through Validation Expressions, which
>   form a simple logic for expressing precisely what kind of validation
>   scrutiny is required. It then allows the use of these expressions as a
>   constraint in various places where trust en credentials are defined.*

**TODO:** The current implementation of validation expressions is not complete;
the framework is in place however, but some vital tests (such as matching
identities and OpenPGP support) have not been made.

The TLS Pool introduces a simple [expression
language](https://github.com/arpa2/tlspool/blob/master/doc/validation.md) for
indicating requirements on validation of TLS handshakes. Simple refers to the
syntax’s complexity, not to the mind set of its users… sorry :)

The basic syntax is an
[RPN](https://en.wikipedia.org/wiki/Reverse_Polish_notation) notation of logic
operations, operating on basic tests that are expressed with operands that are
represented as a single letter or digit. Most of the operands are defined in a
technology-agnostic manner, or variations have been predefined for the various
mechanisms that a TLS connection may employ. For example, it is of vital
importance to follow a certificate chain to a trusted root for X.509
Certificates, and to find a locally trusted OpenPGP key that directly signs one
being offered, but for Kerberos tickets there is no need because the surrounding
infrastructure has already done that if we got a workable ticket within its
window of validity.

It is not very common for end users to handle validation expressions, or at
least that is our current assumption. Administrators however, may need to learn
how these can be written and (perhaps) inserted in a central SteamWorks system
that facilitates users’ TLS Pools.
