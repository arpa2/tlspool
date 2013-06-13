#!/usr/bin/env python

import os
import socket
import time
import libtlsd

print "Creating connection to server"
HOST = 'localhost'    # The remote host
PORT = 10000
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    conn.connect((HOST, PORT))
    conn, cmd = libtlsd.pass_to_daemon(conn, 'start-tls localhost')

    while 1: 
        x = 'quit'#raw_input("go>") 
        if(x=='quit'):
            break
        conn.send(x) 
        print "sent", x 

    print "Closing"
    #s.sendall('quit')

except socket.error as msg:
    print msg

conn.close();