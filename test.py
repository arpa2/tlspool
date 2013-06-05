#!/usr/bin/env python

import os
import socket
import passfd
import time

print "Creating connection to server"
HOST = 'localhost'    # The remote host
PORT = 443
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((HOST, PORT))

print "Sending fd"
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/socketname")
ret = passfd.sendfd(s, conn.fileno(), "start-tls")

print "Send %s bytes" % ret
print "Closing"
s.close()
