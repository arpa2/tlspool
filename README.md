With DNSSEC, we finally have reliable DNS information; with DANE, we finally get proper constraints on server certificates, even self-signed ones. It might be interesting to consider publishing CERT records for client-side certificates in DNS as well, but that would publish detailed contact information for domain users, which would be too supportive of spam and scam.

Another mechanism that is almost completely possible now, is to store the certificates in LDAP and look it up with uid=someone,dc=example,dc=com through a DNS SRV reference to an LDAP server, and to retrieve a userCertificate.  This mechanism could be used by any website that wanted to validate a user's identity or pseudonymity.  Anyone adding DNSSEC to this mix would be improving the security level of their service, so it is a good reason to embrace DNSSEC, if DANE wasn't good enough yet.

What we are looking for is a sort of TLS-wrapper that fulfills the following functions:
-respond to SNI by sending back the right certificate to serve the client
-ask the client for a certificate with uid=,dc=,dc= as its subject name
-validate that its private key is used to prove certificate ownership
-compare that certificate to what is stored in DNS and LDAP
-use a port-dependent plugin module to communicate the client identity and SNI-name to an internal TCP-based process
-share the succeeded connection in a TLS cache for quicker reconnections in the future

In the project you will:
-create a "TLS tunnel" based on GnuTLS and/or OpenSSL and/or SSLtunnel
-design and implement a modular forwarding mechanism
-implement a few example modules, e.g.: http, imap
