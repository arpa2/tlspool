from gnutls.crypto import *
from gnutls.constants import X509_FMT_DER, X509_FMT_PEM

import logging
import ldap
import socket
from unbound import ub_ctx,RR_TYPE_SRV,RR_TYPE_A,RR_TYPE_AAAA
from binascii import a2b_hex, b2a_hex
from hashlib import sha256, sha512

logger = logging.getLogger(__name__)
ctx = ub_ctx()
ctx.add_ta_file('root.key')

flag_dnssec = False
flag_dane =  False
flag_ldap = False

def parse_flags(s):
    flags = s.split(';')
    for flag in flags:
        if flag == 'dnssec':
            flag_dnssec = True
        elif flag == 'dane':
            flag_dnssec = True
            flag_dane = True
        elif flag == 'ldap':
            flag_ldap = True

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
    if(type(cert) == OpenPGPCertificate):
        check_pgp_cert(cert, server_name, port)

    elif(type(cert) == X509Certificate):
        check_x509_cert(cert, server_name, port)

    else:
        logger.debug("No valid certificate found %s", type(cert))

def check_pgp_cert(cert, server_name=None, port=None):
    logger.debug("Validating PGP certificate with uid: %s", cert.uid())
    
    if cert.uid().email:
        logger.debug("Validating user PGP cert")
        check_ldap(cert.uid().email, cert)

    else:
        if server_name:
            if(cert.uid() == server_name):
                logger.debug("Certificate UID matches servername")
            else:
                logger.warning("Certificate UID does not match server_name")

            check_dane(cert, server_name, port)
        else:
            logger.debug("Cannot validate certificate without having a server name to match")

def check_x509_cert(cert, server_name=None, port=None):
    logger.debug("Validating X.509 certificate with serial: %s", cert.serial_number)
    logger.debug("Subject: %s", cert.subject)
    
    if server_name:
        if cert.subject.CN == server_name:
            logger.debug("Certificate CN matches servername")
        else:
            logger.warning("Certificate CN does not match server_name")

        check_dane(cert, server_name, port)
    else:
        logger.debug("Cannot validate certificate without having a server name to match")

def check_ldap(mailaddr, cert):
    mailaddr_split = mailaddr.split('@')
    #Do NS lokup for LDAP server
    logger.debug("Finding PGP key server for %s", mailaddr_split[1])
    s, r = ctx.resolve('_pgpkey-ldap._tcp.%s' % 'openfortress.nl', rrtype=RR_TYPE_SRV)
    
    if s == 0 and r.havedata:
        #Find UID in LDAP
        if not r.secure:
            logger.warning('Query data is not secure.')
            if flag_dnssec:
                raise InsecureLookupException
            if r.bogus:
                raise InsecureLookupException


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
        try:
            for record in records:
                logger.debug('Resolving LDAP server %s', record.target)
                
                #if socket.has_ipv6 :
                #    result = find_in_ldap(mailaddr, base_dn, record.target, record.port, rrtype=RR_TYPE_AAAA)
                result = find_in_ldap(mailaddr, base_dn, record.target, record.port)
                

            #Validate certificate
            if result:
                for dn,entry in result:
                    for pgpKey in entry['pgpKey']:
                        if cert.fingerprint == OpenPGPCertificate(pgpKey).fingerprint:
                            logger.debug('The users certificate matches the one in LDAP')
        except LDAPUserNotFound:
            logger.warning('The user was not found')
    else:
        logger.warning('Unsuccessful lookup or no data returned for rrtype %s.', RR_TYPE_SRV)

def find_in_ldap(mailaddr, base_dn, target_name, target_port, rrtype=RR_TYPE_A):
    s, r = ctx.resolve(target_name, rrtype)
            
    if not r.secure:
        logger.warning('Query data is not secure.')

    if s == 0 and r.havedata:
        for addr in r.data.address_list:
            logger.debug('Lookup user %s on LDAP server %s with basedn %s', mailaddr, addr, base_dn)
            l = ldap.initialize('ldap://%s:%s' % (addr, target_port))
            try:
                result = l.search_s(
                    base_dn,
                    ldap.SCOPE_SUBTREE,
                    '(&(|(pgpUserID=*<%s>*)(pgpUserID=%s))(pgpDisabled=0))' % (mailaddr,mailaddr))
                return result
            except ldap.TIMEOUT:
                logger.debug('TIMEOUT on %s:%s; Trying next server if available', addr, target_port)
                pass
            except ldap.SERVERDOWN:
                logger.debug('SERVERDOWN on %s:%s; Trying next server if available', addr, target_port)
                pass
            except ldap.NO_SUCH_OBJECT:
                raise LDAPUserNotFound()
    else:
        return None
        

def check_dane(cert, server_name, port, protocol='tcp'):
    RR_TYPE_TLSA = 52
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


# Exceptions
class LDAPUserNotFound(Exception):
    pass

class InsecureLookupException(Exception):
    pass

class DNSLookupError(Exception):
    pass
