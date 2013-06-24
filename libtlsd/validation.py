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


class Validator():

    def __init__(self):
        self.flag_dnssec = True
        self.flag_dane =  True
        self.flag_ldap = True
        self.flag_ign_bogus = False

    def parse_flags(self, s):
        flags = s.split(';')
        for flag in flags:
            if flag == 'no-dnssec':
                logger.debug("Set flag no-dnssec")
                self.flag_dnssec = False
            elif flag == 'no-dane':
                logger.debug("Set flag no-dane")
                self.flag_dane = False
            elif flag == 'no-ldap':
                logger.debug("Set flag no-ldap")
                self.flag_ldap = False
            elif flag == 'ignore-bogus':
                logger.debug("Set flag ignore-bogus")
                self.flag_ign_bogus = True

    def parse_dns_labels(self, s):
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

    def check_cert(self, cert, server_name=None, port=None):
        if(type(cert) == OpenPGPCertificate):
            self.check_pgp_cert(cert, server_name, port)

        elif(type(cert) == X509Certificate):
            self.check_x509_cert(cert, server_name, port)

        else:
            logger.debug("No valid certificate found %s", type(cert))

    def check_pgp_cert(self, cert, server_name=None, port=None):
        logger.debug("Validating PGP certificate with uid: %s", cert.uid())
        
        if cert.uid().email:
            logger.debug("Validating user PGP cert")
            if self.flag_ldap:
                self.check_ldap(cert.uid().email, cert)

        else:
            if server_name:
                if(cert.uid() == server_name):
                    logger.debug("Certificate UID matches servername")
                else:
                    logger.warning("Certificate UID does not match server_name")

                if self.flag_dane:
                    self.check_dane(cert, server_name, port)
            else:
                logger.debug("Cannot validate certificate without having a server name to match")

    def check_x509_cert(self, cert, server_name=None, port=None):
        logger.debug("Validating X.509 certificate with serial: %s", cert.serial_number)
        logger.debug("Subject: %s", cert.subject)
        
        # TODO: Distinguish user/domain and validate user in ldap

        if server_name:
            if cert.subject.CN == server_name:
                logger.debug("Certificate CN matches servername")
            else:
                logger.warning("Certificate CN does not match server_name")

            if self.flag_dane:
                self.check_dane(cert, server_name, port)
        else:
            logger.debug("Cannot validate certificate without having a server name to match")

    def check_ldap(self, mailaddr, cert):
        mailaddr_split = mailaddr.split('@')
        #Do NS lokup for LDAP server
        logger.debug("Finding PGP key server for %s", mailaddr_split[1])
        s, r = ctx.resolve('_pgpkey-ldap._tcp.%s' % 'openfortress.nl', rrtype=RR_TYPE_SRV)
        
        if s == 0 and r.havedata:
            #Find UID in LDAP
            self.check_secure(r)

            records=[]
            for record in r.data.raw:
                hexdata = b2a_hex(record)
                records.append(
                    SRVRecord(
                        int(hexdata[0:4], 16),
                        int(hexdata[4:8], 16),
                        int(hexdata[8:12], 16),
                        '.'.join(self.parse_dns_labels(record[6:]))))

            records.sort()

            base_dn = 'dc=%s' % ',dc='.join((mailaddr_split[1].split('.')))
            result = None
            try:
                for record in records:
                    logger.debug('Resolving LDAP server %s', record.target)
                    
                    #if socket.has_ipv6 :
                    #    result = find_in_ldap(mailaddr, base_dn, record.target, record.port, rrtype=RR_TYPE_AAAA)
                    result = self.find_in_ldap(mailaddr, base_dn, record.target, record.port)
                    

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

    def find_in_ldap(self, mailaddr, base_dn, target_name, target_port, rrtype=RR_TYPE_A):
        s, r = ctx.resolve(target_name, rrtype)
                
        self.check_secure(r)
        
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
            

    def check_dane(self, cert, server_name, port, protocol='tcp'):
        RR_TYPE_TLSA = 52
        logger.debug("Resolving: _%d._%s.%s", port, protocol, server_name)
        s, r = ctx.resolve('_%d._%s.%s' % (port, protocol, server_name), rrtype=RR_TYPE_TLSA)

        if s == 0 and r.havedata:
            self.check_secure(r)
            for record in r.data.raw:
                hexdata = b2a_hex(record)
                cert_usage = int(hexdata[0:2], 16)
                selector = int(hexdata[2:4], 16)
                match_type = int(hexdata[4:6], 16)
                tlsa_hash = hexdata[6:]
                
                if(tlsa_hash == self.cert_hash(cert, match_type)):
                    logger.debug('Certificate matches TLSA record')
                else:
                    logger.warning('DANE Error. Certificate does not match')
                    raise DaneError()

        else:
            logger.warning('Unsuccessful lookup or no data returned for rrtype %s.', RR_TYPE_TLSA)
            raise DaneError()


    def cert_hash(self, cert, match_type):
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

    def check_secure(self, r):
        if not r.secure:
            if self.flag_dnssec:
                logger.info('Query data is not secure.')
                raise InsecureLookupException
            if r.bogus:
                if self.flag_ign_bogus:
                    logger.warning('Ignoring bogus query data.')
                else:
                    logger.info('Bogus query data.')
                    raise InsecureLookupException


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
class DaneError(Exception):
    pass
class InsecureLookupException(Exception):
    pass
class DNSLookupError(Exception):
    pass
