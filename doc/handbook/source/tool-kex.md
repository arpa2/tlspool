# Key Exchange Tool

>   *We now turn to a totally different use of TLS, and in fact a new
>   usage scenario, namely for the exchange of keys (or passwords)
>   between users.*

It happens with some frequency that users need to exchange a password.
We have gotten used to doing this over a simple web connection, but we also
know how unreliable this is.  Still, we fall back to it because we have no
other basis of collaboration, not in general at least.

When two users have a TLS Pool, they are also likely to have credentials
setup in them.  And these credentials may be suitable for setting up a
TLS connection.  What would happen if we allowed this connection, and
derived a password from it?  Certainly this is possible, with
[RFC5705](https://tools.ietf.org/html/rfc5705)
offering a framework to derive keys from the master secret that forms
the secret that only the connected TLS endpoints know.

The TLS Pool includes a crude demonstration tool that implements this
idea, by passing the messages of the TLS handshake in a textual form
between two parties.  This form can be exchanged over an existing protocol,
like email, chat or IRC.  The information may be visible to others; it
will be due to mutual authentication that only the right parties connect.

There is a need for two mesages in each direction, so there are a few
hoops to jump through, but they are quite doable.  The first message
may look like this, and the rest are similar:

    -----BEGIN TLS CLIENT HELLO-----
    FgMBAT0BAAE5AwNX56b5uf6GuRJTwQy9WVrNgxJ9LH4+zWa6NDPgu0LnsQAAmMAvwDDAisCLwBPA 
    J8AUwCjAdsB3wBIAngCfwHzAfQAzAGcAOQBrAEUAvgCIAMTAnsCfABbAK8AswIbAh8AJwCPACsAk
    wHLAc8CswK3ACACiAKPAgMCBADIAQAA4AGoARAC9AIcAwwATAJwAncB6wHsALwA8ADUAPQBBALoA
    hADAwJzAnQAKwB3AIMAawB7AIcAbwB/AIsAcAQAAeAAXAAAABQAFAQAAAAAACQADAgABAAAAFgAU
    AAARdGxzcG9vbC5hcnBhMi5sYWL/AQABAAAMAAcGdGVzdGVyACMAAAAKAAwACgAXABgAGQAVABMA
    CwACAQAADQAcABoEAQQDBOAFAQUDBeAGAQYDBuADAQMDAgECAw==
    -----END TLS CLIENT HELLO-----

**TODO:** This tool is not in complete working order at present.  Sorry.
