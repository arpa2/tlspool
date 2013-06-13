import socket
import passfd
import logging
import os, sys
from threading import Thread

from gnutls.crypto import *
from gnutls.connection import *

import PyKCS11

logger = logging.getLogger(__name__)

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

class SessionHandler(Thread):
    def __init__(self, client, address, sess_id):
        Thread.__init__(self, name='SessionHandler')
        self.daemon = True
        self.address = address
        self.clnt_cmd = client
        self.clnt_data = None
        self.sess_id = sess_id
        

    def start_tls(self, server_name=None):
#       cert = X509Certificate(open(certs_path + '/valid.crt').read())
#        key = X509PrivateKey(open(certs_path + '/valid.key').read())
#        ca = X509Certificate(open(certs_path + '/ca.pem').read())
#        crl = X509CRL(open(certs_path + '/crl.pem').read())
#        cred = X509Credentials(cert, key, [ca], [crl])
        cert = OpenPGPCertificate(open(certs_path + '/valid-pgp.pub').read())
        key = OpenPGPPrivateKey(open(certs_path + '/valid-pgp.key').read())
        cred = OpenPGPCredentials(cert, key)
        self.session = ClientSession(self.connection, cred, server_name)
        return self.setup_tls()

    def recv_tls(self):
        cert = OpenPGPCertificate(open(certs_path + '/valid-pgp.pub').read())
        key = OpenPGPPrivateKey(open(certs_path + '/valid-pgp.key').read())
        cred = OpenPGPCredentials(cert, key)
        self.session = ServerSession(self.connection, cred)
        return self.setup_tls()
        
    def setup_tls(self):
        print self.session.server_name
        try:
            logger.info("%d:TLS handshake", self.sess_id)

            self.session.handshake()
            
            logger.debug("%d:Handshake result\n"
                #+"  UID: %s \n"
                #+"  Fingerprint: %s \n"
                +"  Protocol: %s \n"
                +"  KX algorithm: %s \n"
                +"  Cipher: %s \n"
                +"  MAC algorithm: %s \n"
                +"  Compression: %s",
                self.sess_id,
                #self.session.peer_certificate.uid(),
                #self.session.peer_certificate.fingerprint,
                self.session.protocol,
                self.session.kx_algorithm,
                self.session.cipher,
                self.session.mac_algorithm,
                self.session.compression)
      
        except Exception, e:
            logger.error('%d:Handshake failed: %s', self.sess_id, e)
            print self.session.server_name
            return 0

        self.validate_certificate(self.session.peer_certificate)

        self.clnt_data, clnt_fd = socket.socketpair(socket.AF_UNIX)
        return clnt_fd

    def validate_certificate(self, cert):
        if(type(cert) == OpenPGPCertificate):
            print "Validating certificate with uid: %s" % cert.uid()
        if(type(cert) == X509Certificate):
            print "Validating certificate with subject: %s" % cert.subject

        


    def run(self):
        logger.debug("%d:Waiting for fd", self.sess_id)
        fd, msg = passfd.recvfd(self.clnt_cmd)

        logger.debug("%d:Received fd: %s; message: %s", self.sess_id, fd, msg)

        # TODO: find out type of socket

        self.connection = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)

        clnt_fd = 0
        if msg == 'start-tls':
            clnt_fd = self.start_tls()
        if msg.startswith("start-tls "):
            logger.debug("%d:SNI: %s", self.sess_id, msg.split()[1])
            clnt_fd = self.start_tls(msg.split()[1])
        if msg == "recv-tls":
            clnt_fd = self.recv_tls()

        logger.debug("%d:Sending substitute fd: %s", self.sess_id, clnt_fd)
        passfd.sendfd(self.clnt_cmd, clnt_fd)


        # TODO: data threads should be replaced with asyncore
        logger.debug("%d:starting data handlers", self.sess_id)
        handler1 = DataSessionHandler(self.clnt_data, self.session)
        handler1.start()
        handler2 = DataSessionHandler(self.session, self.clnt_data)
        handler2.start()
        logger.info("%d:connection established", self.sess_id)

        while(True):
            command = self.clnt_cmd.recv(4096)
            if(command == 'quit' or len(command) == 0):
                logger.debug("%d:closing client data socket", self.sess_id)
                self.clnt_data.close()

                logger.info("%d:closing tls session", self.sess_id)
                self.session.bye()
                self.session.close()
                
                handler1.stop = True
                handler2.stop = True
                #handler1.join()
                #handler2.join()
                
                logger.debug("%d:stopping %s thread", self.sess_id, self.name)

                logger.debug("%d:closing client cmd socket", self.sess_id)
                self.clnt_cmd.close()

                return
            else:
                logger.debug("%d:unspecified command received from client", self.sess_id)
                self.clnt_cmd.sendall("err: unspecified command")

class DataSessionHandler(Thread):
    stop = False

    def __init__(self, src, dst):
        Thread.__init__(self, name='DataSessionHandler')
        self.src = src
        self.dst = dst


    def run(self):
        while(not self.stop):
            try:
                buf = self.src.recv(4096)
                if(len(buf) <= 0):
                    break
                self.dst.send(buf)
            except:
                logger.error("Unexpected error: %s", sys.exc_info()[0])
                self.stop = True

        logger.debug("stopping %s thread", self.name)
        