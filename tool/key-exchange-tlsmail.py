#!/usr/bin/env python
#
# key-exchange-tlsmail.py is a TLS-based key exchange toy program
#
# This program starts an exchange between users, in a PEM-alike format
# message that users can exchange however they like.  They will agree
# on a key based on RFC 5705.
#
# From: Rick van Rein <rick@openfortress.nl>


import os
import sys
import socket
import threading

import base64

import tlspool


class TLSwrapper (threading.Thread):
	"""A class for wrapping the TLS exchange, and from which we can pickup
	   the traffic so it can be encoded in a PEM-style format.
	   
	   This procedure is wrapped into a threading.Thread because that will
	   allow a main program to continue and ask for the intermediate state
	   from the TLS exchange (and pass it around in a PEM-style format)
	   while this thread is blocked on the STARTTLS call, as part of the
	   ongoing handshake.  Yeah, the TLS Pool itself is asynchronous, but
	   the use of a wrapper library conceals that from individual clients.
	"""

	def __init__ (self, server=False):
		"""Create an inactive TLS Pool conncetion, with a public side
		   TLS connection through tls2pem and pem2tls functions.
		"""
		threading.Thread.__init__ (self)
		self.server = server
		(self.tlsint, self.tlsext) = socket.socketpair ()
		self.hold = None

	def starttls (self, localid, remotid):
		"""Spark off the activities in this object.
		"""
		self.localid = localid
		self.remotid = remotid
		self.start ()

	def starttls_finished (self):
		"""Wait until the TLS handshake has finished (or failed).
		"""
		self.join ()

	def stoptls (self):
		"""Terminate the activities in this object.
		"""
		#NONEX# self.stop ()
		self.cleanup ()
		# self.tlsint.close ()
		# self.tlsext.close ()
		if self.hold:
			self.hold.close ()

	def run (self):
		"""Start the TLS exchange.  Both client and server will run one
		   of these, either in the same process (demo mode, -d) or each
		   in their own process (on their own machine) in modes -c and -s,
		   respectively.
		"""
		pingdata = (tlspool.TLSPOOL_IDENTITY_V2, tlspool.PIOF_FACILITY_ALL_CURRENT)
		pingdata = tlspool.ping (*pingdata)
		facilities = pingdata [1]
		# Ensure that TLS is supported by TLS Pool and client libraries
		assert (facilities & tlspool.PIOF_FACILITY_STARTTLS)
		if self.server:
			roles = tlspool.PIOF_STARTTLS_LOCALROLE_SERVER | tlspool.PIOF_STARTTLS_REMOTEROLE_CLIENT | tlspool.PIOF_STARTTLS_DETACH
		else:
			roles = tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT | tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER | tlspool.PIOF_STARTTLS_DETACH
		tlsdata = {
			'service': 'telnet',
			'flags': roles,
			'localid': self.localid,
			'remoteid': self.remotid,
			'ipproto': socket.IPPROTO_TCP,
			'timeout': 0xffffffff		# ~0 means: Infinite timeout
		}
		self.cnx = tlspool.Connection (self.tlsint, **tlsdata)
		try:
			self.hold = self.cnx.starttls ()
		except:
			print 'Failure from STARTTLS'
			raise

	#
	# Did we leave anything lying around?  Better clean up then.
	#
	def cleanup (self):
		pass

	def cmdline (self, other=False):
		"""Construct a commandline, sowing how we could be called.
		   If so requested, construct the commandline for the other side.
		"""
		if self.server:
			srvopt = '-s'
		else:
			srvopt = '-c'
		if other:
			id1 = self.remotid
			id2 = self.localid
		else:
			id1 = self.localid
			id2 = self.remotid
		return sys.argv [0] + ' -s "' + id1 + '" "' + id2 + '"'

	def tls2pem (self, msgtype, docstr=None):
		"""Message in PEM-ish style, with the given docstring preceding it.
		"""
		tlsmsg = self.tlsext.recv (4096)
		pemblah = ''
		if docstr:
			pemblah = pemblah  + '\n'
			pemblah = pemblah  + docstr + '\n'
			pemblah = pemblah + '\n'
		pemblah = pemblah + '-----BEGIN TLS ' + msgtype.upper () + '-----\n'
		pemblah = pemblah + base64.encodestring (tlsmsg)
		pemblah = pemblah + '-----END TLS ' + msgtype.upper () + '-----\n'
		pemblah = pemblah + '\n'
		return pemblah

	def pem2tls (self, pemblah, msgtype):
		"""Parse a PEM-ish message, skipping any surrounding text.
		"""
		try:
			(pre,post) = pemblah.split ('-----BEGIN TLS ' + msgtype.upper () + '-----\n', 1)
			(mid,post) = post.split ('\n-----END TLS ' + msgtype.upper () + '-----', 1)
			self.tlsext.send (base64.decodestring (mid))
		except:
			print
			print '##### Failed to decode... please try again #####'
			print
			raise

	def genpwd (self, reqlen):
		"""Use RFC 5705 to derive a password from the TLS master key.
		   This inherits properties like PFS fro the key exchange!
		"""
		return self.cnx.prng (reqlen,
				label='EXPERIMENTAL-TLS-WRAPPED-AS-PEM')

def readpem (blockname):
	print 'Please enter TLS ' + blockname + ':\n scan> ',
	pem = ''
	line = ''
	scan = 1
	while True:
		line = sys.stdin.readline ().strip ()
		if scan and line == '-----BEGIN TLS ' + blockname + '-----':
			scan = 0
		if not scan:
			pem = pem + line
		if line == '-----END TLS ' + blockname + '-----':
			break
		print 'scan> ' if scan else 'data> ',
	return pem


def runscript (client, server):

	if client:
		print """
		#
		# You want to settle on a password with a friend.
		# You start key-exchange-tlsmail.py on your commandline
		# and you forward its output over email:
		#
		"""

		tlscli = TLSwrapper ()
		#TODO# Commandline identities override for -c mode but not for -d
		tlscli.starttls ('testcli@tlspool.arpa2.lab', 'testsrv@tlspool.arpa2.lab')

		pemblah = tlscli.tls2pem ('CLIENT HELLO', """
Hello """ + tlscli.remotid + """!
""" """
I'd like to settle on a password with you, without anyone but us to find
out what the password is.  I found that key-exchange-tlsmail.py can do this.
On your end, you should run the following command,
""" """
""" + tlscli.cmdline (other=True) + """
""" """
and put in the clearly marked data below, including the marker lines.
The program will provide a response that you can send back in a reply,
and after two more messages we'll each see the password being printed.
""" """
Looking forward to your reply!
""" """
Yours truly,
""" + tlscli.localid + """
""" """
""")

		print pemblah
	else:
		pemblah = readpem ('CLIENT HELLO')

	if server:
		print """
		#
		# The remote end receives the message, starts this program
		# and enters the received message into their tool.
		#
		# The response follows.
		#
		"""

		tlssrv = TLSwrapper (server=True)
		#TODO# Commandline identities override for -s mode but not for -d
		tlssrv.starttls ('testsrv@tlspool.arpa2.lab', 'testcli@tlspool.arpa2.lab')

		tlssrv.pem2tls (pemblah, 'CLIENT HELLO')

		pemblah = tlssrv.tls2pem ('SERVER HELLO', """
Howdy """ + tlssrv.remotid + """,
""" """
I did as you asked.  My tool then output the following, which I am hereby
returning to you.  I suppose your tool is waiting for it already, just like
mine is now awaiting your second round input.
""" """
Ciao,
""" + tlssrv.localid + """
""")

		print pemblah
	else:
		pemblah = readpem ('SERVER HELLO')

	if client:
		print """
		#
		# There, you got it.  Your friend did as you asked, and you
		# received his initial response.  There's one more thing
		# for you to send him, and then you process his output and
		# get the password printed out.
		#
		"""

		tlscli.pem2tls (pemblah, 'SERVER HELLO')

		pemblah = tlscli.tls2pem ('CLIENT FINISH', """
Hah, """ + tlscli.remotid + """...
""" """
One more round to go, namely this back-and-forth, and we'll each have our
passwords printed out!  And we'll even hear it if something went wrong on
either side.
""" """
Isn't it funny how useful this security protocol can get when you play it
out over email or chat between two friends?
""" """
Grinn,
""" + tlscli.localid + """
""")

		print pemblah
	else:
		pemblah = readpem ('CLIENT FINISH')

	if server:
		print """
		#
		# You feed it into your tool and, as your friend predicted,
		# you are seeing the password already.
		#
		# Now quickly return the styled text to your friend,
		# and of course not include the password, and both you
		# and your friend have it.  And nobody else does!
		#
		"""

		pemblah = tlssrv.pem2tls (pemblah, 'CLIENT FINISH')

		pemblah = tlssrv.tls2pem ('SERVER FINISH', """
Hi """ + tlssrv.remotid + """!
""" """
Grinn.  This is awesome.  I'm not sending you the password itself, and still
you can derive the same value as I am doing over here.  Crypto is so cool!
""" """
I'm assuming we included Diffie-Hellman in the message exchange too, right?
Because then it'll even have Perfect Forward Secrecy.  Tadaaa!
""" """
Forever yours,
""" + tlssrv.localid + """
""")

		tlssrv.starttls_finished ()
		print
		print 'Handshake finished on server'

		#HUH# tlspool.control_reattach (tlssrv.ctlkey)

		print
		print
		print
		print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
		#ALT# print ':'.join ( [ '%02x' % ord (c) for c in tlssrv.genpwd (32) ] )
		print base64.b64encode (tlssrv.genpwd (16)).rstrip ('=')
		print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
		print
		print
		print 'Now please send the response to your peer, so they can construct the same password'
		print
		print pemblah
		print
		print
		print
	else:
		pemblah = readpem ('SERVER FINISH')

	if client:
		pemblah = tlscli.pem2tls (pemblah, 'SERVER FINISH')

		tlscli.starttls_finished ()
		print
		print 'Handshake finished on client'

		print """
		#
		# Finally, there's the final response from your friend.
		# He already has the password and... (check)... has
		# been so good not to send it to you.  No need either,
		# the TLS protocol can derive it just as well!
		#
		"""

		#ABOVE# tlscli.pem2tls (pemblah, 'SERVER FINISH')

		#HUH# tlspool.control_reattach (tlscli.ctlkey)

		print
		print
		print
		print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
		#ALT# print ':'.join ( [ '%02x' % ord (c) for c in tlscli.genpwd (32) ] )
		print base64.b64encode (tlscli.genpwd (16)).rstrip ('=')
		print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
		print
		print
		print

	if client or server:
		print """
		#
		# It's been a messy day.  Time to shut down.  Thanks for paying attention!
		#
		"""

	if client:
		tlscli.stoptls ()

	if server:
		tlssrv.stoptls ()

help = 0
exitval = 1
if len (sys.argv) != 4:
	if len (sys.argv) != 2:
		help = 1
	elif sys.argv [1] == '-d':
		server = 1
		client = 1
		exitval = 0
	else:
		help = 1
		if sys.argv [1] == '-h':
			exitval = 0
elif sys.argv [1] in ['-s', '-c']:
	server = sys.argv [1] == '-s'
	client = sys.argv [1] == '-c'
	exitval = 0
else:
	help = 1

if help:
	sys.stderr.write ('Usage: ' + sys.argv [0] + ' -d|-h\n       ' + sys.argv [0] + ' -s|-c yourID remoteID\n')
	sys.exit (exitval)

runscript (client, server)

