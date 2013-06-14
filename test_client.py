#!/usr/bin/env python

import os
import socket
import time
import libtlsd

print "Creating connection to server"
HOST = 'localhost'    # The remote host
PORT = 10000
USER_INPUT = False
conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    conn.connect((HOST, PORT))
    conn, cmd = libtlsd.pass_to_daemon(conn, 'start-tls localhost')

    while USER_INPUT: 
        x = raw_input(">") 
        if(x=='quit'):
            cmd.sendall('quit')
            break
        conn.send(x) 
        print "sent", x 

    if not USER_INPUT:
        conn.send('test123')
        cmd.sendall('quit')

    print "Closing"
    
except socket.error as msg:
    print msg

conn.close();