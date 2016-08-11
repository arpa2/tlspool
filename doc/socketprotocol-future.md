# Socket Protocol v2

> *This is an experimental investigation into a DER-based socket protocol.
> This work has NO FORMAL STATUS yet.*

See the [related issue](https://github.com/arpa2/tlspool/issues/42) for reasons.

## Extensibility and Parsing

We permit extensions of the ASN.1 `SEQUENCE` and `CHOICE` constructs, thus enabling
future extensions to both request/response formats and the types of requests and
responses that may be carried.  Unrecognised extensions will always lead to an
error from the TLS Pool, and must be taken as an error by its clients.  (However,
when a client receives an unrecognised callback, it will report an error.)

We break off parsing at the points of extensibility.  So we do not enter a `CHOICE`,
but instead parse general structures until we get there, and then use a suitable
collection of recognised choices to continue parsing.  This is shown in the
ASN.1 descriptions below with an `ANY` field and a written explanation of what
it should contain.

This tactic enables us, for instance, to match on request identity,
or to recognise that we were sent a callback instead of a response,
and in case its contained structure is unrecognisable we can send an `ERROR`
back to the TLS Pool to let it know that the callback was refused by the client.
Such an error does usually cause another command to return `ERROR`, but this time
it'll be a command that returns, not a (nested) callback.

Most of this general logic can be embedded in a simple wrapper that takes in a
parsing descriptor (such as those from
[Quick DER](https://github.com/vanrein/quick-der))
and processes it in conjunction with the data structure passed in and out.

## Individual Structures and their Compositions

As with the original socket protocol, the same structures are used in requests
and responses, so an invocation of the TLS Pool is like passing a structure
as a variable parameter.

We define a number of `CHOICE` wrappers, which are meant to wrap alternatives that
may be recognised.  For instance, the TLS Pool is likely to accept all possible
alternatives, whereas a client may be focussed on a STARTTLS procedure, and thus
accept only that in response, or the usual side-tracks to an error or identity
request.

Where we defined command codes in the original socket protocol, we will now
use application tags instead to mark the various commands.  This enables us to
combine alternatives into a `CHOICE` structure and retain parseability.  Note
how this means that the parser will detect failures in the format as well as
in the options replied to us.

