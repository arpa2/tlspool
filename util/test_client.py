#!/usr/bin/env python

import os
import socket
import passfd
import time

print "Creating connection to server"
HOST = 'localhost'    # The remote host
PORT = 443
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    conn.connect((HOST, PORT))
    print "Sending fd"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/tmp/tlsd.sock")

    ret = passfd.sendfd(s, conn.fileno(), "start-tls")
    print "Send %s bytes" % ret
    print "Receiving fd..."
    fd, msg = passfd.recvfd(s)

    print "  fd: %s" % fd
    print "  message: %s" % msg

    conn = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)

    while 1: 
        x = raw_input("go>") 
        if(x=='quit'):
            break
        conn.send(x) 
        print "sent", x 

    print "Closing"
    s.sendall('quit')

except socket.error as msg:
    print msg

conn.close();