#!/usr/bin/python

import sys
import socket

sys.path.append ('.')
import tlspool

if len (sys.argv) >= 2:
    website = sys.argv [1]
else:
    website = 'nlnet.nl'

if len (sys.argv) >= 3:
	tlspool.open_poolhandle (sys.argv [2])

sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM)
sox.connect ( (website, 443) )

cli2srv = (	tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT |
		tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER )
cnx = tlspool.Connection (sox, service='http', flags=cli2srv)

cnx.tlsdata.localid='testcli@tlspool.arpa2.lab'
cnx.tlsdata.remoteid=website

web = cnx.starttls ()

web.send ('GET / HTTP/1.0\r\nHost: ' + website + '\r\n\r\n')

dta = web.recv (4096)
while dta != '':
	sys.stdout.write (dta)
	dta = web.recv (4096)

cnx.close ()

