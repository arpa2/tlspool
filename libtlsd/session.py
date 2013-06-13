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
certs_path = os.path.join(script_path, 'util/certs')

cert = OpenPGPCertificate(open(certs_path + '/valid-pgp.pub').read())
key = OpenPGPPrivateKey(open(certs_path + '/valid-pgp.key').read())
cred = OpenPGPCredentials(cert, key)


class SessionHandler(Thread):
    def __init__(self, client, address):
        Thread.__init__(self, name='SessionHandler')
        self.daemon = True
        self.address = address
        self.clnt_cmd = client
        self.clnt_data = None
        

    def start_tls(self):
        self.session = ClientSession(self.connection, cred)
        try:
            logger.info("TLS handshake")
            self.session.handshake()
            peer_cert = session.peer_certificate

            logger.debug("Handshake result\n\
                \tUID: %s \n\
                \tFingerprint: %s \n\
                \tProtocol: %s \n\
                \tKX algorithm: %s \n\
                \tCipher: %s \n\
                \tMAC algorithm: %s \n\
                \tCompression: %s",
                (peer_cert.uid(),
                peer_cert.fingerprint,
                self.session.protocol,
                self.session.kx_algorithm,
                self.session.cipher,
                self.session.mac_algorithm,
                self.session.compression))
        
        except Exception, e:
            logger.error('Handshake failed:', e)

        self.clnt_data, clnt_fd = socket.socketpair(socket.AF_UNIX)
        return clnt_fd

    def run(self):
        logger.debug("Waiting for fd")
        fd, msg = passfd.recvfd(self.clnt_cmd)

        logger.debug("Received fd: %s; message: %s", fd, msg)

        self.connection = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)

        if msg == "start-tls":
            clnt_fd = self.start_tls()
            logger.debug("Sending substitute fd: %s", fd)
            passfd.sendfd(self.clnt_cmd, clnt_fd)


        # data threads should be replaced with asyncore
        logger.debug("starting data handlers")
        handler1 = DataSessionHandler(self.clnt_data, self.session)
        handler1.start()
        handler2 = DataSessionHandler(self.session, self.clnt_data)
        handler2.start()
        logger.info("connection established")

        while(True):
            command = self.clnt_cmd.recv(4096)
            if(command == 'quit'):
                logger.debug("closing client data socket")
                self.clnt_data.close()

                logger.info("closing tls session")
                self.session.bye()
                self.session.close()
                
                handler1.stop = True
                handler2.stop = True
                #handler1.join()
                #handler2.join()
                
                logger.debug("stopping %s thread", self.name)

                logger.debug("closing client cmd socket")
                self.clnt_cmd.close()

                return
            else:
                logger.debug("unspecified command received from client")
                conn.sendall("err: unspecified command")

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
        