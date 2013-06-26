#!/usr/bin/env python

"""Synchronous server using python-gnutls"""

import sys
import os
import socket
import libtlsd

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
HOST = '0.0.0.0'
PORT = 10000
sock.bind((HOST, PORT))
sock.listen(1)

print "Listening on port %d" % PORT

while True:
    try:
        conn, address = sock.accept()
        print "Incoming", address
        conn, cmd, status, msg = libtlsd.pass_to_daemon(conn, 'recv-tls no-dnssec')

        if status > 0:
            print msg
            sys.exit(0)

        print "Identity of peer is: %s" % msg

        while(True):
            try:
                buf = conn.recv(1024)
                print 'Received: %d %s' % (len(buf), buf.rstrip())
                if(len(buf) <= 0):
                    break
            except KeyboardInterrupt:
                print "Ctrl C - Terminating Session; Press Ctrl+C again to stop the server"
                break
            except:
                print "Unexpected error:", sys.exc_info()[0]
                break

        print "Closing session"
        conn.close()
    except KeyboardInterrupt:
        print "Ctrl C - Stopping server"
        sys.exit(1)
    except:
        print "Unexpected error:", sys.exc_info()[0]
