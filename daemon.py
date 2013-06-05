#!/usr/bin/env python

import os
import socket
import passfd
import sys
from threading import Thread

from gnutls.crypto import *
from gnutls.connection import *


script_path = os.path.realpath(os.path.dirname(sys.argv[0]))
certs_path = os.path.join(script_path, 'certs')

cert = OpenPGPCertificate(open(certs_path + '/valid-pgp.pub').read())
key = OpenPGPPrivateKey(open(certs_path + '/valid-pgp.key').read())
cred = OpenPGPCredentials(cert, key)


class SessionHandler(Thread):
    def __init__(self, session, address):
        Thread.__init__(self, name='SessionHandler')
        self.setDaemon(True)
        self.session = session
        self.address = address

    def start_tls(self):
        session = ClientSession(self.connection, cred)
        try:
            print "Handshake"
            session.handshake()
            peer_cert = session.peer_certificate

            print '  UID:          ', peer_cert.uid()
            print '  Fingerprint:  ', peer_cert.fingerprint
            print '  Protocol:     ', session.protocol
            print '  KX algorithm: ', session.kx_algorithm
            print '  Cipher:       ', session.cipher
            print '  MAC algorithm:', session.mac_algorithm
            print '  Compression:  ', session.compression
        
        except Exception, e:
            print 'Handshake failed:', e
        session.send("test\r\n")
        buf = session.recv(1024)
        session.bye()
        session.close()
        return 0

    def run(self):
        print "Receiving fd..."
        fd, msg = passfd.recvfd(self.session)

        print "  fd: %s" % fd
        print "  message: %s" % msg

        self.connection = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)

        if msg == "start-tls":
            fd = self.start_tls()

        print "Closing"
        self.session.close()


print "Creating socket"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    os.remove("/tmp/socketname")
except OSError:
    pass

print "Binding to socket"
s.bind("/tmp/socketname")

print "Waiting for connection"
s.listen(1)

while True:
    conn, addr = s.accept()
    handler = SessionHandler(conn, addr)
    handler.start()