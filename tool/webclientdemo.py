#!/usr/bin/env python
#
# webclientdemo.py -- Access the website configured below, and retrieve path /
#
# From: Rick van Rein <rick@openfortress.nl>

import sys
import socket

# Demo path
sys.path.append ('../lib')
import tlspool

# Configuration
#
webhost = 'research.arpa2.org'
#
tlsdata = {
	'localid': 'testcli@tlspool.arpa2.lab',
	'remoteid': 'testsrv@tlspool.arpa2.lab',
}
#
# End of Configuration

privdata = { }

sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM, 0)
sox.connect ( ('::1', 22335) )

retval = tlspool.starttls_client (sox, tlsdata, privdata)

print 'RETVAL =', retval
print 'PRIVDATA =', privdata
print 'TLSDATA =', tlsdata

if retval == 0:
	plainfd = privdata ['plainfd']
	plainfd.send ('GET / HTTP/1.0\r\nHost: ' + webhost + '\r\n\r\n')
	print 'OUTPUT:'
	txt = plainfd.recv (1024)
	while txt != '':
		print txt,
		txt = plainfd.recv (1024)

