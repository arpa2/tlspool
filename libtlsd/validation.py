from gnutls.crypto import *
from gnutls.constants import X509_FMT_DER, X509_FMT_PEM

import logging
import unbound
from binascii import a2b_hex, b2a_hex
from hashlib import sha256, sha512

logger = logging.getLogger(__name__)
ctx = unbound.ub_ctx()
ctx.add_ta_file('root.key')

def check_cert(cert, server_name=None, port=None):
    #if(type(cert) == OpenPGPCertificate):
    #    logger.debug("Validating PGP certificate with uid: %s", cert.uid())
    if(type(cert) == X509Certificate):
        logger.debug("Validating X.509 certificate with serial: %s", cert.serial_number)
        logger.debug("Subject: %s",cert.subject)
        
        if(cert.check_hostname(server_name)):
            logger.debug("CN matches servername")
        else:
            logger.warning("CN does not match server_name")

        check_dane(cert, server_name, port)
        

def check_dane(cert, server_name, port):
    s, r = ctx.resolve('_%d._tcp.%s' % (port, server_name), rrtype=52)

    if s == 0 and r.havedata:
        if not r.secure:
            logger.warning('query data is not secure.')
        # If we are here the data was either secure or insecure data is accepted
        for record in r.data.raw:
            hexdata = b2a_hex(record)
            mtype = int(hexdata[4:6],16)
            print '%d %d %d %s', (int(hexdata[0:2],16), int(hexdata[2:4],16), mtype, hexdata[6:])
            print cert_hash(cert, mtype)
            if(hexdata[6:] == cert_hash(cert, mtype)):
                logger.info('Cert matches')
            else:
                logger.warning('DANE Error. cert does not match')

    else:
        logger.warning('Unsuccesful lookup or no data returned for rrtype %s.', rrtype)


def cert_hash(cert, mtype):
    cert_der = cert.export(X509_FMT_DER)
    print b2a_hex(cert_der)
    
    if mtype == 0:
        return b2a_hex(cert_der)
    elif mtype == 1:
        return sha256(cert_der).hexdigest()
    elif mtype == 2:
        return sha512(cert_der).hexdigest()
    else:
        return False