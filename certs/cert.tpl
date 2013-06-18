# X.509 Certificate options
#
# DN options

# The organization of the subject.
organization = "System and Network Engineering"

# The organizational unit of the subject.
unit = "RP2"

# The locality of the subject.
# locality =

# The state of the certificate owner.
#state = "Attiki"

# The country of the subject. Two letter code.
country = NL

# The common name of the certificate owner.
cn = "Rene Klomp"

# A user id of the certificate owner.
uid = "rklomp"

# Set domain components
#dc = "oslo"
#dc = "studlab"
#dc = "os3"
#dc = "nl"

# If the supported DN OIDs are not adequate you can set
# any OID here.
# For example set the X.520 Title and the X.520 Pseudonym
# by using OID and string pairs.
#dn_oid = 2.5.4.12 Dr. 
#dn_oid = 2.5.4.65 jackal

# This is deprecated and should not be used in new
# certificates.
# pkcs9_email = "none@none.org"

# An alternative way to set the certificate's distinguished name directly
# is with the "dn" option. The attribute names allowed are:
# C (country), street, O (organization), OU (unit), title, CN (common name),
# L (locality), ST (state), placeOfBirth, gender, countryOfCitizenship, 
# countryOfResidence, serialNumber, telephoneNumber, surName, initials, 
# generationQualifier, givenName, pseudonym, dnQualifier, postalCode, name, 
# businessCategory, DC, UID, jurisdictionOfIncorporationLocalityName, 
# jurisdictionOfIncorporationStateOrProvinceName,
# jurisdictionOfIncorporationCountryName, XmppAddr, and numeric OIDs.

#dn = "cn=Nik,st=Attiki,C=GR,surName=Mavrogiannopoulos,2.5.4.9=Arkadias"
dn = "C=NL,O=SNE,OU=RP2,CN=Rene Klomp,UID=rklomp,DC=oslo,DC=studlab,DC=os3,DC=nl"

# The serial number of the certificate
#serial = 007

# In how many days, counting from today, this certificate will expire.
expiration_days = 700

# X.509 v3 extensions

# A dnsname in case of a WWW server.
#dns_name = "www.none.org"
#dns_name = "www.morethanone.org"

# A subject alternative name URI
#uri = "http://www.example.com"

# An IP address in case of a server.
#ip_address = "192.168.1.1"

# An email in case of a person
email = "rene.klomp@os3.nl"

# Challenge password used in certificate requests
#challenge_password = 123456

# Password when encrypting a private key
#password = secret

# An URL that has CRLs (certificate revocation lists)
# available. Needed in CA certificates.
#crl_dist_points = "http://www.getcrl.crl/getcrl/"

# Whether this is a CA certificate or not
#ca

# for microsoft smart card logon
# key_purpose_oid = 1.3.6.1.4.1.311.20.2.2

### Other predefined key purpose OIDs

# Whether this certificate will be used for a TLS client
tls_www_client

# Whether this certificate will be used for a TLS server
#tls_www_server

# Whether this certificate will be used to sign data (needed
# in TLS DHE ciphersuites).
signing_key

# Whether this certificate will be used to encrypt data (needed
# in TLS RSA ciphersuites). Note that it is preferred to use different
# keys for encryption and signing.
encryption_key

# Whether this key will be used to sign other certificates.
#cert_signing_key

# Whether this key will be used to sign CRLs.
#crl_signing_key

# Whether this key will be used to sign code.
#code_signing_key

# Whether this key will be used to sign OCSP data.
#ocsp_signing_key

# Whether this key will be used for time stamping.
#time_stamping_key

# Whether this key will be used for IPsec IKE operations.
#ipsec_ike_key

### end of key purpose OIDs

# When generating a certificate from a certificate
# request, then honor the extensions stored in the request
# and store them in the real certificate.
#honor_crq_extensions

# Path length contraint. Sets the maximum number of
# certificates that can be used to certify this certificate.
# (i.e. the certificate chain length)
#path_len = -1
#path_len = 2

# OCSP URI
# ocsp_uri = http://my.ocsp.server/ocsp

# CA issuers URI
# ca_issuers_uri = http://my.ca.issuer

# Certificate policies
# policy1 = 1.3.6.1.4.1.5484.1.10.99.1.0
# policy1_txt = "This is a long policy to summarize"
# policy1_url = http://www.example.com/a-policy-to-read

# policy2 = 1.3.6.1.4.1.5484.1.10.99.1.1
# policy2_txt = "This is a short policy"
# policy2_url = http://www.example.com/another-policy-to-read


# Options for proxy certificates
# proxy_policy_language = 1.3.6.1.5.5.7.21.1


# Options for generating a CRL

# next CRL update will be in 43 days (wow)
#crl_next_update = 43

# this is the 5th CRL by this CA
#crl_number = 5

