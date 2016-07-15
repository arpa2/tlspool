#!/usr/bin/python

import sys
import socket

sys.path.append ('.')
import tlspool

sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM)
sox.connect ( ('www.arpa2.net', 443) )

cnx = tlspool.Connection (sox, service='http', flags=0x0d)

cnx.tlsdata.localid='testcli@tlspool.arpa2.lab'
cnx.tlsdata.remoteid='www.arpa2.net'

cnx = cnx.starttls ()

cnx.send ('GET / HTTP/1.0\r\nHost: www.arpa2.net\r\n\r\n')

dta = cnx.recv (4096)
while dta != '':
	print dta,
	dta = cnx.recv (4096)

cnx.close ()

