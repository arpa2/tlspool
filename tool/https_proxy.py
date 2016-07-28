#!/usr/bin/python
#
# https_proxy -- Pass on HTTPS connections but sit in between with the TLS Pool
#
# This program accepts the CONNECT request from RFC 2817.  The argument to this
# method is server:port, which will be used to connect, and set the server-side
# identity.  The TLS Pool is used twice; once for the connection to the server
# and once for the connection to the client after having reported 200 OK.  The
# latter connection will be signed on-the-fly.
#
# The intention of this program is to run for the single user of a desktop
# machine.  It is a proxy to support the client, not the server.  Specifically,
# it enables the user to replace local-software SSL/TLS stacks, and replace
# it with the implementation of the TLS Pool, including the extra security
# mechanisms, identity selection and centralised control that it offers.
#
# Regarding efficiency, the connections are established from Python, calling
# the TLS Pool for all the hard work.  Once the unwrapping and rewrapping of
# the connection has been setup, it is entirely left to the TLS Pool.  The
# price for the proxy then is an additional encryption and decryption, after
# the extra time to exchange two handshakes in sequence (as a result of how
# a HTTPS_PROXY has been specified to work in RFC2817).
# TODO: At present, the Python module tlspool.py is unsuitable for threading,
# and so this implementation takes one request at a time.  This can lead to
# additional sequencing of TLS handshakes, especially when multiple resources
# are accessed at the same time.  This is a matter of implementation of the
# Python module, which should probably be improved at some point.  The code
# below already holds a commented-out threading variation.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import socket
import threading

import tlspool

if len (sys.argv) == 2:
	tlspool.open_poolhandle (sys.argv [1])

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn


class Handler (BaseHTTPRequestHandler):

	def do_GET (self):
		self.send_response (400, 'Bad Request')
		self.end_headers ()
		self.wfile.write ('Only use me to proxy HTTPS please!\r\n')
		return

	do_POST = do_GET

	def do_CONNECT (self):
		#
		# Parse the request line, CONNECT servername:port HTTP/1.1
		#
		try:
			servername, port = self.path.split (':')
			port = int (port)
		except:
			self.send_response (400, 'Bad Request')
			return
		#
		# Connect to the server
		#
		# srvtls = socket.socket (socket.AF_INET6, socket.SOCK_STREAM, 0)
		# if srvtls.connect_ex ( (servername, port) ) != 0:
		# 	srvtls.close ()
		if True:
			srvtls = socket.socket (socket.AF_INET, socket.SOCK_STREAM, 0)
			if srvtls.connect_ex ( (servername, port) ) != 0:
				srvtls.close ()
				srvtls = -1
		if srvtls == -1:
			self.send_response (408, 'Request Timeout')
			return
		#
		# Start TLS on the server connection through the TLS Pool.
		# This is done without indicating or limiting the client
		# identity, and anything the TLS Pool wants to do to set
		# that is permitted.  This enables the user to benefit from
		# the TLS Pool's plethora of connection options.
		#
		#OLD# # Since the socket library implements these differently from
		#OLD# # common sockets (?!?) we shall apply Python's usual wrapper.
		#OLD# #
		#OLD# _srvtxt, _clitxt = socket.socketpair ()
		#OLD# srvtxt = socket._socketobject (_sock=_srvtxt)
		#OLD# clitxt = socket._socketobject (_sock=_clitxt)
		#OLD# print 'server TLS socket ::', type (srvtls)
		#OLD# print 'server TXT socket ::', type (srvtxt)
		# print 'server TXT plainfd =', srvtxt.fromfd
		#OLD# srvcnx = tlspool.Connection (cryptsocket=srvtls, plainsocket=srvtxt)
		srvcnx = tlspool.Connection (cryptsocket=srvtls)
		srvcnx.tlsdata.flags = ( tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT |
					 tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER |
					 tlspool.PIOF_STARTTLS_FORK |
					 tlspool.PIOF_STARTTLS_DETACH )
		srvcnx.tlsdata.remoteid = servername
		srvcnx.tlsdata.ipproto = socket.IPPROTO_TCP
		srvcnx.tlsdata.service = 'http'
		try:
			clitxt = srvcnx.starttls ()
		except:
			self.send_response (403, 'Forbidden')
			return
		#
		# Report the success of setting up the backend connection
		#
		self.send_response (200, 'Connection Established')
		self.end_headers ()
		#
		# Now pass the client connection through the TLS Pool too.
		# The plaintext connections from the client and server will
		# be connected.
		#
		clitls = self.wfile
		#OLD# print 'client TLS socket ::', type (clitls)
		#OLD# print 'client TXT socket ::', type (clitxt)
		clicnx = tlspool.Connection (cryptsocket=clitls, plainsocket=clitxt)
		clicnx.tlsdata.flags = ( tlspool.PIOF_STARTTLS_LOCALROLE_SERVER |
				 	 tlspool.PIOF_STARTTLS_REMOTEROLE_CLIENT |
				 	 tlspool.PIOF_STARTTLS_FORK |
				 	 tlspool.PIOF_STARTTLS_DETACH |
				 	 tlspool.PIOF_STARTTLS_IGNORE_REMOTEID |
				 	 tlspool.PIOF_STARTTLS_LOCALID_ONTHEFLY )
		clicnx.tlsdata.localid = servername
		clicnx.tlsdata.ipproto = socket.IPPROTO_TCP
		clicnx.tlsdata.service = 'http'
		try:
			clicnx.starttls ()
		finally:
			srvcnx.close ()


class ThreadedHTTPServer (ThreadingMixIn, HTTPServer):
	"""Handle requests in a separate thread."""
	pass


#TODO# Use a plain server for now!
if __name__ == '__main__':
	sockaddr = ('0.0.0.0', 8080)
	server = ThreadedHTTPServer ( sockaddr, Handler)
	print 'HTTPS proxy started on %s:%d -- stoppable with Ctrl-C' % sockaddr
	server.serve_forever()

