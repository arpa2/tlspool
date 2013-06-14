from gnutls.crypto import *
import logging

logger = logging.getLogger(__name__)

def validate(cert):
    if(type(cert) == OpenPGPCertificate):
        logger.debug("Validating PGP certificate with uid: %s", cert.uid())
    if(type(cert) == X509Certificate):
        logger.debug("Validating X.509 certificate with subject: %s", cert.subject)
        logger.debug("CN: %s",cert.subject.CN)
        logger.debug("EMAIL: %s",cert.subject.EMAIL)
        logger.debug("UID: %s",cert.subject.UID)
