from gnutls.crypto import *
from gnutls.constants import X509_FMT_DER, X509_FMT_PEM

import logging
import ldap
from unbound import ub_ctx,RR_TYPE_SRV
from binascii import a2b_hex, b2a_hex
from hashlib import sha256, sha512

logger = logging.getLogger(__name__)
ctx = ub_ctx()
ctx.add_ta_file('root.key')

def parse_dns_labels(s):
    ptr = 0
    ret = []
    while True:
        label_len = ord(s[ptr])
        if label_len == 0:
            return ret
        new_label = ''
        for _ in range(label_len):
            ptr += 1
            new_label += s[ptr]
        ret.append(new_label)
        ptr += 1



def check_cert(cert, server_name=None, port=None):
    logger.debug("entering check_cert %s", type(cert))
    
    if(type(cert) == OpenPGPCertificate):
        check_pgp_cert(cert, server_name, port)

    elif(type(cert) == X509Certificate):
        check_x509_cert(cert, server_name, port)

    else:
        logger.debug("No valid certificate found")

def check_pgp_cert(cert, server_name=None, port=None):
    logger.debug("Validating PGP certificate with uid: %s", cert.uid())
    
    if cert.uid().email:
        logger.debug("Validating user PGP cert")
        mailaddr_split = cert.uid().email.split('@')

        #Do NS lokup for LDAP server
        logger.debug("Finding PGP key server for %s", mailaddr_split[1])
        s, r = ctx.resolve('_pgpkey-ldap._tcp.%s' % 'openfortress.nl', rrtype=RR_TYPE_SRV)
        
        if s == 0 and r.havedata:
            #Find UID in LDAP
            if not r.secure:
                logger.warning('Query data is not secure.')

            records=[]
            for record in r.data.raw:
                hexdata = b2a_hex(record)
                records.append(
                    SRVRecord(
                        int(hexdata[0:4], 16),
                        int(hexdata[4:8], 16),
                        int(hexdata[8:12], 16),
                        '.'.join(parse_dns_labels(record[6:]))))

            records.sort()

            base_dn = 'dc=%s' % ',dc='.join((mailaddr_split[1].split('.')))
            result = None
            for record in records:
                logger.debug('Lookup user %s on LDAP server %s with basedn %s', cert.uid().email, record.target, base_dn)
                s2, r2 = ctx.resolve(record.target)
        
                l = ldap.initialize('ldap://%s:%s' % (record.target, record.port))
                try:
                    result = l.search_s(
                        base_dn,
                        ldap.SCOPE_SUBTREE,
                        '(&(|(pgpUserID=*<%s>*)(pgpUserID=%s))(pgpDisabled=0))' % (cert.uid().email,cert.uid().email))
                    break;
                except ldap.TIMEOUT, ldap.SERVERDOWN:
                    logger.debug('TIMEOUT or SERVERDOWN; Trying next server if available')
                    pass
                except ldap.NO_SUCH_OBJECT:
                    logger.debug('The user was not found')
                    break;
            
            #Validate certificate
            if result:
                for dn,entry in result:
                    for pgpKey in entry['pgpKey']:
                        if cert.fingerprint == OpenPGPCertificate(pgpKey).fingerprint:
                            logger.debug('The users certificate matches the one in LDAP')
        
        else:
            logger.warning('Unsuccessful lookup or no data returned for rrtype %s.', RR_TYPE_SRV)

    else:
        if server_name:
            if(cert.uid() == server_name):
                logger.debug("UID matches servername")
            else:
                logger.warning("UID does not match server_name")

            check_dane(cert, server_name, port)
        else:
            logger.debug("Cannot validate certificate without having a server name to match")

def check_x509_cert(cert, server_name=None, port=None):
    logger.debug("Validating X.509 certificate with serial: %s", cert.serial_number)
    logger.debug("Subject: %s", cert.subject)
    
    if server_name:
        if cert.subject.CN == server_name:
            logger.debug("CN matches servername")
        else:
            logger.warning("CN does not match server_name")

        check_dane(cert, server_name, port)
    else:
        logger.debug("Cannot validate certificate without having a server name to match")


def check_dane(cert, server_name, port, protocol='tcp'):
    RR_TYPE_TLSA = 52
    logger.debug(cert_hash(cert, 1))

    logger.debug("Resolving: _%d._%s.%s", port, protocol, server_name)
    s, r = ctx.resolve('_%d._%s.%s' % (port, protocol, server_name), rrtype=RR_TYPE_TLSA)

    if s == 0 and r.havedata:
        if not r.secure:
            logger.warning('Query data is not secure.')
        for record in r.data.raw:
            hexdata = b2a_hex(record)
            cert_usage = int(hexdata[0:2], 16)
            selector = int(hexdata[2:4], 16)
            match_type = int(hexdata[4:6], 16)
            tlsa_hash = hexdata[6:]
            
            if(tlsa_hash == cert_hash(cert, match_type)):
                logger.debug('Certificate matches TLSA record')
            else:
                logger.warning('DANE Error. Certificate does not match')

    else:
        logger.warning('Unsuccessful lookup or no data returned for rrtype %s.', RR_TYPE_TLSA)


def cert_hash(cert, match_type):
    # DER export in gnutls library does not work. Convert manually from PEM to DER
    cert_pem = cert.export()
    from binascii import a2b_base64
    lines = cert_pem.replace(" ",'').split()
    cert_der = a2b_base64(''.join(lines[1:-1]))

    if match_type == 0:
        return b2a_hex(cert_der)
    elif match_type == 1:
        return sha256(cert_der).hexdigest()
    elif match_type == 2:
        return sha512(cert_der).hexdigest()
    else:
        return False


class SRVRecord:
    def __init__(self, priority, weight, port, target):
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def __lt__(self, other):
        return self.priority < other.priority

