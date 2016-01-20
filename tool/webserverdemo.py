#!/usr/bin/env python
#
# webserverdemo.py -- Simple web server with TLS.
#
# From: Rick van Rein <rick@openfortress.nl>

import sys

from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

# Demo path
sys.path.append ('../lib')
import tlspool

# Configuration
#
serverid = 'testsrv@tlspool.arpa2.lab'
#
# End of Configuration


class SecureHTTPServer (HTTPServer):

	def get_request (self):
		"""The get_request method overrides the default function,
		   and wraps TLS security around the newly received
		   request/connection before passing it down.
		"""
		(cryptfd, upaddr) = HTTPServer.get_request (self)
		tlsdata = {
			'localid': serverid,
		}
		privdata = { }
		if tlspool.starttls_server (cryptfd, tlsdata, privdata) == -1:
			raise IOError ('Failed to setup HTTPS')
		plainfd = privdata ['plainfd']
		dnaddr = tlsdata ['remoteid']
		#DEBUG# print 'WAS:', cryptfd, '::', type (cryptfd), upaddr
		#DEBUG# print 'NOW:', plainfd, '::', type (plainfd), dnaddr
		#WONTWORK# return (plainfd, dnaddr)
		return (plainfd, upaddr)

#
# Serve local files insecurely
http_server = HTTPServer (('127.0.0.1', 8080), SimpleHTTPRequestHandler)
#SKIP# http_server.serve_forever ()

#
# Serve local files securely
https_server = SecureHTTPServer (('127.0.0.1', 8181), SimpleHTTPRequestHandler)
https_server.serve_forever ()

