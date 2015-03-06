#!/usr/bin/env python
#
# tlspool-kex is a TLS-based key exchange toy program
#
# This program starts an exchange between users, in a PEM-alike format
# message that users can exchange however they like.  They will agree
# on a key based on RFC 5705.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import socket
import threading

import base64
import struct

try:
	import fdsend
except:
	sys.stderr.write ('This utility assumes you have the fdsend python library installed\n')
	sys.exit (1)




#
# A class for the TLS exchange
#
class TLSconnection (threading.Thread):

	#
	# Create an inactive TLS Pool connection, with a public side
	# TLS connection through tls2pem and pem2tls functions.
	#
	def __init__ (self, server=False):
		threading.Thread.__init__ (self)
		self.server = server
		self.poolfd = None
		self.tlsint, self.tlsext = socket.socketpair ()

	#
	# Spark off the activities in this object
	#
	def starttls (self, localid, remotid):
		self.localid = localid
		self.remotid = remotid
		self.poolfd = socket.socket (socket.AF_UNIX, socket.SOCK_STREAM, 0)
		self.poolfd.connect ('/var/run/tlspool.sock')
		self.start ()

	#
	# Terminate the activities in this object
	#
	def stoptls (self):
		#NONEX# self.stop ()
		self.cleanup ()

	#
	# Client and server both run the starttls() command
	#
	def run (self):
		cmd = struct.pack ('HHI' + '136s',
				666, 0, 0x00000010,
				'20130710tlspool@openfortress.nl')
		cmd = struct.pack ('376s', cmd)
		# print 'Sending command', str (cmd).encode ('hex')
		fdsend.sendfds (self.poolfd.fileno (), cmd)
		# print 'Sent'
		(resp,ranc) = fdsend.recvfds (self.poolfd.fileno (), 376, numfds=32)
		# print 'Received response', resp.encode ('hex')
		# print 'Received ancillary', ranc
		if self.server:
			cmdcode = 0x00000021
		else:
			cmdcode = 0x00000020
		cmd = struct.pack ('HHI' + 'IIBH128s128s', 
				12345, 0, cmdcode,
				0x00000200,
				0,
				socket.IPPROTO_TCP,
				0,
				self.localid,
				self.remotid)
		cmd = struct.pack ('376s', cmd)
		anc = [ self.tlsint ]
		# print 'Sending command', str (cmd).encode ('hex')
		# print 'Sending ancillary', anc
		fdsend.sendfds (self.poolfd.fileno (), cmd, fds=anc)
		# print 'Sent'
		(resp,ranc) = fdsend.recvfds (self.poolfd.fileno (), 376, numfds=1)
		# print 'Received response', resp.encode ('hex')
		# print 'Received ancillary', ranc

	#
	# Did we leave anything lying around?  Better clean up then.
	#
	def cleanup (self):
		if self.poolfd:
			self.poolfd.close ()
			self.poolfd = None

	#
	# Construct a commandline, showing how we could be called.
	# If need be, construct the commandline for the other side.
	#
	def cmdline (self, other=False):
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

	#
	# Message in PEM-ish style, with the given docstring before it
	#
	def tls2pem (self, msgtype, docstr=None):
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

	#
	# Parse a PEM-ish message, skipping any surrounding text
	#
	def pem2tls (self, pemblah, msgtype):
		try:
			(pre,post) = pemblah.split ('-----BEGIN TLS ' + msgtype.upper () + '-----\n', 1)
			(mid,post) = post.split ('\n-----END TLS ' + msgtype.upper () + '-----', 1)
			self.tlsext.send (base64.decodestring (mid))
		except:
			print
			print '##### Failed to decode... please try again #####'
			print

	#
	# Use RFC 5705 to derive a password from the TLS master key.
	# This inherits properties like PFS from the key exchange!
	#
	def genpwd (self):
		return 'TODO:RFC5705'

print """
#
# You want to settle on a password with a friend.  You start tlspool-kex
# on your commandline and you forward its output over email:
#
"""

tlscli = TLSconnection ()
tlscli.starttls ('testcli@tlspool.arpa2.lab', 'testsrv@tlspool.arpa2.lab')

pemblah = tlscli.tls2pem ('CLIENT HELLO', """
Hello """ + tlscli.remotid + """!
""" """
I'd like to settle on a password with you, without anyone but us to find
out what the password is.  I found that tlspool-kex can do this.  On your
end, you should run the following command,
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

print """
#
# The remote end receives the message, starts tlspool-kex and enters the
# received message into their tool.  The response follows.
#
"""

tlssrv = TLSconnection (server=True)
tlssrv.starttls ('testsrv@tlspool.arpa2.lab', 'testcli@tlspool.arpa2.lab')

tlssrv.pem2tls (pemblah, 'CLIENT HELLO')

pemblah = tlssrv.tls2pem ('SERVER HELLO', """
Howdy """ + tlssrv.remotid + """,
""" """
I did as you asked.  My tool then output the following, which I am hereby
returning to you.  I suppose your tool is waiting for it already, just like
mine is awaiting your second round input.
""" """
Ciao,
""" + tlssrv.localid + """
""")

print pemblah

print """
#
# There, you got it.  Your friend did as you asked, and you received his
# initial response.  There's one more thing for you to send him, and then
# you process his output and get the password printed out.
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
Isn't it funny how useful the web protocol can get when you play it out
between two friends?
""" """
Grinn,
""" + tlscli.localid + """
""")

print pemblah

print """
#
# You feed it into your tool and, as your friend predicted, you are seeing
# the password already.  Now quickly return the styled text to your friend,
# and of course not include the password, and both of us have it.
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

print pemblah

print
print
print
print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
print tlscli.genpwd ()
print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
print
print
print

print """
#
# Finally, there's the final response from your friend.  He already has the
# password and... (check)... has been so good not to include it.  No need
# either, the TLS protocol can derive it just as well!
#
"""

tlscli.pem2tls (pemblah, 'SERVER FINISH')

print
print
print
print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
print tlscli.genpwd ()
print '##### DO NOT SHIP THIS, IT IS YOUR PASSWORD #####'
print
print
print

print """
#
# It's been a messy day.  Time to shut down.  Thanks for paying attention!
#
"""

tlscli.stoptls ()
tlssrv.stoptls ()

