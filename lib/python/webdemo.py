#!/usr/bin/python

import sys
import socket

sys.path.append ('.')
import tlspool

sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM)
sox.connect ( ('www.arpa2.net', 443) )

cli2srv = (	tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT |
		tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER )
cnx = tlspool.Connection (sox, service='http', flags=cli2srv)

cnx.tlsdata.localid='testcli@tlspool.arpa2.lab'
cnx.tlsdata.remoteid='www.arpa2.net'

web = cnx.starttls ()

web.send ('GET / HTTP/1.0\r\nHost: www.arpa2.net\r\n\r\n')

dta = web.recv (4096)
while dta != '':
	sys.stdout.write (dta)
	dta = web.recv (4096)

cnx.close ()

