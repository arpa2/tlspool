import socket
import passfd
import logging
import os, sys
import select
from threading import Thread
import libtlsd.validation

from gnutls.crypto import *
from gnutls.connection import *

import PyKCS11

logger = logging.getLogger(__name__)

script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

BUF_SIZE = 4096
DELAY = 0.0001

class SessionHandler(Thread):
    def __init__(self, client, address, sess_id):
        Thread.__init__(self, name='SessionHandler')
        self.daemon = True
        self.address = address
        self.clnt_cmd = client
        self.clnt_data = None
        self.sess_id = sess_id
        self.stop = False
        self.server_name = None
        self.remote_port = None

    def start_tls(self, server_name=None):
        cert = OpenPGPCertificate(open(certs_path + '/personal-pgp.pub').read())
        key = OpenPGPPrivateKey(open(certs_path + '/personal-pgp.key').read())
        cred = OpenPGPCredentials(cert, key)
        self.session = ClientSession(self.connection, cred, server_name)
        return self.setup_tls()

    def recv_tls(self):
        cert = OpenPGPCertificate(open(certs_path + '/server-pgp.pub').read())
        key = OpenPGPPrivateKey(open(certs_path + '/server-pgp.key').read())
        cred = OpenPGPCredentials(cert, key)
        self.session = ServerSession(self.connection, cred)
        return self.setup_tls()
        
    def setup_tls(self):
        try:
            logger.debug("TLS handshake")

            self.session.handshake()
            
            logger.debug("Handshake result\n"
                +"  Protocol: %s \n"
                +"  KX algorithm: %s \n"
                +"  Cipher: %s \n"
                +"  MAC algorithm: %s \n"
                +"  Compression: %s",
                self.session.protocol,
                self.session.kx_algorithm,
                self.session.cipher,
                self.session.mac_algorithm,
                self.session.compression)
      
        except Exception, e:
            logger.error('Handshake failed: %s', e)
            return 0

        libtlsd.validation.check_cert(self.session.peer_certificate, self.server_name, self.remote_port)

        self.clnt_data, clnt_fd = socket.socketpair(socket.AF_UNIX)
        return clnt_fd

    def process_cmd(self, data):
        logger.debug("Processing CMD: %s", data)
        if(data == 'quit'):
            self.clnt_cmd.sendall("OK")
            self.close_connections()        
        else:
            logger.debug("unspecified command received from client")
            self.clnt_cmd.sendall("err: unspecified command")

    def close_connections(self):
        logger.debug("Closing client data socket")
        try:
            self.clnt_data.shutdown()
        except:
            pass
        self.clnt_data.close()

        logger.info("Closing tls session")
        self.session.bye()
        try:
            self.session.shutdown()
        except:
            pass
        self.session.close()
 
        logger.debug("Closing client cmd socket")
        try:
            self.clnt_cmd.shutdown()
        except:
            pass
        self.clnt_cmd.close()
        self.stop = True

    def run(self):
        logger.debug("Starting %s", self.name)
        
        logger.debug("Waiting for fd")
        fd, msg = passfd.recvfd(self.clnt_cmd)

        logger.debug("Received fd: %s; message: %s", fd, msg)

        # Find out type of socket
        temp_s = socket.fromfd(fd, socket.AF_UNIX, socket.SOCK_STREAM)
        styp = temp_s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
        # IPv6 or IPv4?
        if ':' in temp_s.getsockname()[0]:
            sfam = socket.AF_INET6
        else:
            sfam = socket.AF_INET
        del temp_s

        logger.debug("Creating socket from fd %s with family %d and type %d", fd, sfam, styp)
        self.connection = socket.fromfd(fd, sfam, styp)
        self.remote_port = self.connection.getpeername()[1]

        clnt_fd = -1
        msg_split = msg.split()
        if msg_split[0] == 'start-tls':
            #format of msg is: start-tls [server_name [flags]]
            if len(msg_split) > 1:
                logger.debug("SNI: %s", msg_split[1])
                self.server_name = msg_split[1]
            if len(msg_split) > 2:
                validation.parse_flags(msg_split[2])
            clnt_fd = self.start_tls()
        if msg_split[0] == "recv-tls":
            #format of msg is: recv-tls [flags]
            clnt_fd = self.recv_tls()

        logger.debug("Sending substitute fd: %s", clnt_fd)
        passfd.sendfd(self.clnt_cmd, clnt_fd)

        # Create list of all sockets in correct order to always read the session socket first
        inputs = []
        inputs.append(self.session)
        inputs.append(self.clnt_data)
        inputs.append(self.clnt_cmd)
        
        logger.info("Connection setup done forwarding all traffic...")
        while(not self.stop):
            inputready, outputready, exceptready = select.select(inputs, [], [])

            for s in inputready:
                data = s.recv(BUF_SIZE)
                
                if data:
                    if s is self.clnt_cmd:
                        self.process_cmd(data)
                    elif s is self.clnt_data:
                        self.session.send(data)
                    elif s is self.session:
                        self.clnt_data.send(data)
                else:
                    # Interpret empty result as closed connection and close all
                    # Ignore termination of cmd socket
                    if s is self.clnt_cmd:
                        logger.info('Client cmd socket was closed')
                        inputs.remove(self.clnt_cmd)
                    else:
                        self.close_connections()

        logger.debug("Terminating %s", self.name)