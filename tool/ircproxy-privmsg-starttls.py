#!/usr/bin/env python
#
# ircproxy-privmsg-starttls.py -- Enforce STARTTLS over PRIVMSG
#
# This is an intermediate hop between an IRC client and an IRC server.  It
# monitors the flow of commands, and recognises a few and treats them
# specially.
#
# The reasoning is that group chat is public inasfar as the server cannot
# provide encryption; private messaging however, should be properly
# protected against eavesdropping, including form channel operators.
#
# To this end, the named commands, which are intended as end-to-end commands,
# are wrapped into TLS, and communicated under its cloak.  The resulting TLS
# protection is end-to-end, and it is rigidly applied to the said commands.
#
# The TLS data is sent as base64 without line breaks; lines may be split but
# these are then separately base64-encoded.  Each such line is prefixed with
# the word "TLS".
#
# To establish which party serves as client and which as server, the end points
# send a series of STARTxxx words, including "STARTTLS", ending with a random
# string of 1 to 32 bytes/characters in the range 0x21 to 0x7e, inclusive.
# The strings are compared with basic strcmp(); equality means that the TLS
# attempt is cancelled; when unequal, the lower value becomes the client and
# the higher the server (think "client" < "server").  To enforce the client role,
# issue the lowest string "!" and to enforce the server role, issue the highest
# string "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -- in both cases, the risk is that
# the other side is equally stubborn and TLS cannot be negotiated.  When both
# sides have sent one of these commands (as PRIVMSG), the TLS can be further
# setup, which is done through the TLS Pool.
#
# Note that a future TLS extension might implement the same negotiation in TLS,
# in which case this external negotiation will be deprecated and the argument
# to STARTTLS may be made optional, or it may be ignored in whole or in part.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import string
import time
import socket
import select
import threading
import random

import base64
import struct

import SocketServer


prng = random.Random ()


try:
	import fdsend
except:
	sys.stderr.write ('This utility assumes you have the fdsend python library installed\n')
	sys.exit (1)


#
# Script parameters
#
ircserver = ( ( 'irc.arpa2.org', 6667) )
ircproxy  = ( ( '::1',           6667) )


#
# Check if the string contains a '\0' character, which is illegal in
# IRC message according to RFC 1459.
#
def hasnul (irctext):
	return chr (0) in irctext


#
# Split an IRC text into lines, split by CR-LF or either, and ignoring
# empty lines.  Note that the last portion is not ready for processing
# yet; it will need expansion with upcoming IRC text.  In fact, if this
# appears not to be the case then the last portion will be '' and can
# still be safely prefixed without immediate processing to upcoming
# IRC text.
#
def irctext2lines (txt):
	if hasnul (txt):
		return None
	txt.replace ('\r', '\n')
	lines = txt.split ('\n')
	return (lines [:-1], lines [-1])


#
# Map a (prefix,command,arguments) structure back to IRC command line syntax
#
def cmd2ircline ( (pfix,cmd,args) ):
	if pfix:
		ircline = ':' + pfix + ' '
	else:
		ircline = ''
	ircline = ircline + cmd
	for a in args [:-1]:
		ircline = ircline + ' ' + a
	for a in args [-1:]:
		ircline = ircline + ' :' + a
	ircline = ircline + '\r\n'
	return ircline

#
# Parse an IRC line, meaning something split by CR-LF (or either, really,
# since empty lines are ignored and separate CR or LF are ill-defined).
#
# RFC 1459 defines the NUL character (code 0) as illegal, on grounds of
# programming problems in C.
#
# Returns (prefix-or-None, command, ircwords-or-middles)
#
def ircline2words (ircline):
	i = ircline.find (' :')
	if i >= 0:
		trailing = ircline [i+2:]
		ircline = ircline [:i]
	else:
		trailing = None
	ircwords = ircline.split (' ')
	if len (ircwords) > 1 and ircwords [0] [:1] == ':':
		prefix = ircwords [0] [1:]
		ircwords = ircwords [1:]
	else:
		prefix = None
	command = ircwords [0].upper ()
	args = ircwords [1:]
	if trailing:
		args.append (trailing)
	return (prefix, command, args)

#
# Map a nick-name-format to a user@domain, as in nick@name.format
# (where the first dash becomes an @, later dashes become a dot, but
# multiple-dash is mapped to one dash less).
#
def nick2nai (nick, dash1map='@'):
	dashwillbe = dash1map
	parts = nick.split ('-')
	retval = parts [0]
	for part in parts [1:]:
		if part [:1] == '-':
			retval = retval + part
		else:
			retval = retval + dashwillbe + part
			dashwillbe = '.'
	return retval


#
# The PrivateChannel is a channel through which TLS-encrypted messages
# are transferred between peers.  Specific interactions, such as the
# PRIVMSG to something that is not a channel (channel names start with
# a '#' char) pass through this intermediate, and are transformed into
# other messages with privacy protection and/or authentication.
# Each PrivateChannel object is dedicated to a particular remote peer,
# and is able to send messages, as well as to swallow them.
#
# In later versions, we may decide to split into an abstract level of
# PrivateChannel and specific mechanisms, such as TLS.  This would
# enable other transports like GSS-API and SSH to be used as well.
#
class PrivateChannel ():

	def __init__ (self, ircprox, localid, remotid):
		"""Start a new PrivateChannel.  The server can be
		   reached over ircprox.send_to_server(), which will
		   ensure proper locking.  The communication is
		   between the given localid and remotid (both in
		   nick form, see nick2nai(), and anything passing
		   over the PrivateChannel will be sent as a PRIVMSG
		   targeted at remotid, followed by TLS and one line
		   of base64-encoded TLS binary data.  Large TLS data
		   portions may be split over multiple lines, but
		   each is separately base64-encoded, meaning, each
		   line has its own "=" sign trailer.
		"""
		assert (remotid [:1] != '#')
		self.ircprox = ircprox
		self.localid = localid
		self.remotid = remotid
		self.localid_nai = nick2nai (localid)
		self.remotid_nai = nick2nai (remotid)
		self.localhs = None
		self.remoths = None
		self.plaindownbuf = ''
		self.poolcrypt, self.chancrypt = socket.socketpair ()
		self.poolplain, self.chanplain = socket.socketpair ()
		print 'PrivateChannel crypt @pool =', self.poolcrypt, '@chan =', self.chancrypt
		print 'PrivateChannel plain @pool =', self.poolplain, '@chan =', self.chanplain
		self.insecure = 0
		#TODO# Following should not return before done
		# self.start ()
		self.initiate_starttls_handshake ()

	def cleanup (self):
		pass

	def handle_upload_plain_cmd (self, (pfix,cmd,args)):
		#TODO#
		pass

	def handle_download_crypt_cmd (self, (pfix,cmd,args)):
		"""Process a command in triple form (pfix,cmd,args) that
		   arrived from the server, and has been determined to
		   fit the scope of this PrivateChannel.
		"""
		if len (args) != 3 or cmd.upper () != 'PRIVMSG':
			pass	# Exceptional cases handled below
		if 'STARTTLS' in args [1].upper ().split (','):
			handle_download_starttls_handshake ( (pfix,cmd,args) )
			return
		elif args [1].upper () in ['TLS'] and self.poolcrypt is not None:
			tlsdata = base64.b64decode (''.join (args [2:]))
			self.poolcrypt.write (tlsdata)
			tmpbuf = self.plaindownbuf
			while select.select ([self.poolplain], [], [], 0.0) != ([],[],[]):
				#TODO:TEST# tmpbuf = tmpbuf + self.poolplain.recv (1024)
				tmpbuf = tmpbuf + self.poolplain.recv (1)
			(lines, self.plaindownbuf) = irctext2lines (tmpbuf)
			for req in lines:
				#
				# Prefix the *authenticated* remote identity
				# Ignore pfix, rather use TLS-authenticated remotid
				# Ignore args [0], which is how they're calling us
				realcmd = ':' + self.remotid + ' ' + req
				self.ircprox.cli.write (realcmd + '\r\n')
			return
		#
		# TODO:OPTION: Refuse the attempt to do a non-PRIVMSG exchange
		# self.ircprox.upload_cmd ( (None,
		# 	'404',	# Cannot send to channel (not without TLS!)
		# 	[self.localid]) )
		# Optionally deliver insecurely
		self.insecure = self.insecure + 1
		self.ircprox.cli.write (cmd2ircline ( (pfix,cmd,args) ))
		#
		# Ensure that STARTTLS handshake is being proposed (again)
		self.starttls_tlspool_attempt ()
		return

	def handle_download_starttls_handshake (self, (pfix,cmd,args)):
		"""Receive a STARTTLS handshake from the download direction.
		"""
		# Ignore pfix, rather rely on TLS-authenticated remotid
		assert (cmd.upper () == 'PRIVMSG')
		assert (len (args) == 3)
		assert (args [1].upper () == 'STARTTLS')
		self.remoths = args [2]
		self.starttls_tlspool_attempt ()

	def upload_tls_encrypted_cmdline (self, enc_cmdline):
		"""Process an encrypted IRC command line and forward it to
		   the IRC server.  Note that the localid is not sent as
		   part of the command; the receiving end will be better
		   off adding the remotid that it has authenticated through
		   the TLS Pool.
		"""
		cmdln64 = base64.b64encode (enc_cmdline)
		cmd = (None,
			'PRIVMSG',
			# ' '.join (
				[ self.remotid,
				'TLS',
				 cmdln64 ]
			# )
		)
		ircprox.upload_cmd (cmd)

	def initiate_starttls_handshake (self):
		"""Send a STARTTLS handshake in the upload direction.
		"""
		global prng
		self.localhs = ''.join (prng.sample (string.uppercase, 10))
		triple = (
			None,
			'PRIVMSG',
			[ self.remotid, 'STARTTLS', self.localhs ]
		)
		self.ircprox.upload_cmd (triple)
		self.starttls_tlspool_attempt ()

	def starttls_tlspool_attempt (self):
		"""After a STARTTLS handshake is sent or received, test
		   if the handshake is complete and if so, proceed by
		   starting the TLS Pool process.
		"""
		if self.localhs is None:
			#
			# Local side has not sent STARTTLS yet
			self.initiate_starttls_handshake ()
		if self.remoths is None:
			#
			# Remote has not sent STARTTLS yet
			return
		if self.localhs == self.remoths:
			#
			# Explicit cancellation of the handshake
			self.ircprox.download_cmd (
				(':' + self.remotid,
				'PRIVMSG',
				[self.localid,
					'STARTTLS cancelled (you might try again though)']) )
		#
		# Now initiate the TLS Pool connection
		pingstr = tlspool.TLSPOOL_IDENTITY_V2
		print 'Sending ping', pingstr
		pingstr = tlspool.ping (pingstr)
		print 'Received ping', pingstr
		if self.server:
			roles = tlspool.PIOF_STARTTLS_LOCALROLE_SERVER | tlspool.PIOF_STARTTLS_REMOTEROLE_CLIENT | tlspool.PIOF_STARTTLS_DETACH
		else:
			roles = tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT | tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER | tlspool.PIOF_STARTTLS_DETACH
		print 'Requesting STARTTLS'
		tlsdata = {
			'flags': roles,
			'localid': self.localid_nai,
			'remoteid': self.remotid_nai,
			'ipproto': socket.IPPROTO_TCP,
			'plainfd': self.poolplain
		}
		privdata = { }
		print 'DEBUG: Calling starttls with tlsdata =', tlsdata
		if tlspool.starttls (self.poolcrypt, tlsdata, privdata) != 0:
			print 'STARTTLS was mutually agreed, but it failed during setup'
			self.localhs = None
			self.remoths = None
			return
		print 'Successfully returned from STARTTLS; localid =', tlsdata.localid, 'and remoteid =', tlsdata.remoteid
		#
		# Success -- we are now protected by TLS
		self.handle_download_cmd ( (None, 'PRIVMSG', self.localid + ' :This private chat is protected by TLS') )
		if tlsdata.remoteid != '':
			self.handle_download_cmd ( (None, 'PRIVMSG', self.localid + ' :Remote party authenticated as ' + tlsdata.remoteid) )
		else:
			self.handle_download_cmd ( (None, 'PRIVMSG', self.localid + ' :CAUTION, the remote party was not authenticated') )
		if tlsdata.localid != '':
			self.handle_download_cmd ( (None, 'PRIVMSG', self.localid + ' :We identified ourselves to them as ' + tlsdata.localid) )
		else:
			self.handle_download_cmd ( (None, 'PRIVMSG', self.localid + ' :NOTE, we did not authenticate to the other side') )
		if self.insecure > 0:
			#
			# Report (undelivered) insecure messages loudly
			warn = 'WARNING: ' + self.remotid + ' sent ' + str (self.insecure) + ' messages sent before TLS protection!'
			self.extsox.send ('PRIVMSG ' + self.remotid + ' :' + warn + '\r\n')
			self.handle_download_cmd (ircline2words (warn))
			self.insecure = 0

	#
	# Terminate the activities in this object
	#
	def stoptls (self):
		#NONEX# self.stop ()
		raise NotImplementedError ()
		self.cleanup ()


#
# The IRC Server is a pretty simple TCP Server
#
# It splits lines and interprets commands in both directions
#
class IRCHandler (SocketServer.BaseRequestHandler):

	def __init__ (self, x,y,z):
		self.nick = None
		self.oldnick = None
		self.peerprivchan = { }
		self.srvlock = threading.Lock ()
		print 'IRC Handler initialised'
		print 'Calling super...'
		SocketServer.BaseRequestHandler.__init__ (self, x,y,z)
		print 'Called  super...'

	def upload_cmd (self, triple):
		req = cmd2ircline (triple)
		print '>>>', req.strip ()
		self.srvlock.acquire ()
		try:
			self.srv.send (req)
		finally:
			self.srvlock.release ()

	def download_cmd (self, triple):
		rsp = cmd2ircline (triple)
		print '<<<', rsp.strip ()
		self.cli.send (rsp)

	def have_privchan (self, rid):
		if not self.peerprivchan.has_key (rid):
			print 'Initiating TLS via PRIVMSG to', rid
			privchan = PrivateChannel (self, self.nick, rid + '-tlspool-arpa2-lab') #TODO#FIXED#
			self.peerprivchan [rid] = privchan
			print 'Initiated  TLS via PRIVMSG to', rid
		privchan = self.peerprivchan [rid]
		print 'Returning self.peerprivchan ["' + rid + '"] ==', privchan
		return privchan

	def handle_upload (self, (pfix,cmd,args) ):
		if cmd == 'NICK' and len (args) >= 1:
			self.oldnick = self.nick
			self.nick = args [0]
			print 'Set old NICK to', self.oldnick, 'and new NICK to', self.nick
			self.upload_cmd ( (pfix,cmd,args) )
		elif cmd == 'PRIVMSG' and len (args) >= 2:
			alldst = args [0].split (',')
			dirdst = [ d for d in alldst if d [:1] == '#' ]
			tlsdst = [ d for d in alldst if d [:1] != '#' and d != '' ]
			if dirdst != []:
				print 'Sending plaintext PRIVMSG to', ' '.join (dirdst)
				argsup = [','.join (dirdst)] + args [1:]
				self.upload_cmd ( (pfix,cmd,argsup) )
			#DONOTHIDEPLAINTEXT# args = [','.join (tlsdst)] + args [1:]
			for td in tlsdst:
				print 'Requiring TLS for PRIVMSG to', td
				privchan = self.have_privchan (td)
				print 'privchan ==', privchan
				privchan.handle_upload_plain_cmd ( (pfix,cmd,args) )
		else:
			self.upload_cmd ( (pfix,cmd,args) )

	def handle_download (self, (pfix,cmd,args) ):
		cmdu = cmd.upper ()
		if cmd in ['432','433','436']:		# NICK disapproved
			self.nick = self.oldnick
		elif cmdu == 'PRIVMSG' and len (args) >= 2:
			alldst = args [0].split (',')
			dirdst = [ d for d in alldst if d [:1] == '#' ]
			tlsdst = [ d for d in alldst if d [:1] != '#' and d != '' ]
			rid = pfix.split ('!') [0]
			if dirdst != []:
				print 'Sending plaintext PRIVMSG from', rid
				argsup = [','.join (dirdst)] + args [1:]
				self.download_cmd ( (pfix,cmd,argsup) )
			#DONOTHIDEPLAINTEXT# args = [','.join (tlsdst)] + args [1:]
			for td in tlsdst:
				print 'Requiring TLS for PRIVMSG from', rid
				privchan = self.have_privchan (rid)
				print 'privchan ==', privchan
				privchan.handle_download_crypt_cmd ( (pfix,cmd,args) )
		elif cmdu == 'PRIVMSG':
			# ALT/OPTION: Permit old-mode PRIVMSG until /STARTTLS or /SECRET
			print 'Rejecting PRIVMSG without TLS formatting'
			self.upload_cmd ( (None, '404', 'TODO:CHANNAME :Private chat enforces STARTTLS') )
		else:
			self.download_cmd ( (pfix,cmd,args) )

	def handle (self):
		"""self.request is a TCP socket for IRC"""
		self.cli = self.request
		self.srv = socket.socket (socket.AF_INET6, socket.SOCK_STREAM, 0)
		self.srv.connect (ircserver)
		sox = [self.cli, self.srv]
		more = True
		reqbuf = ''
		rspbuf = ''
		while more:
			rsox, _, _ = select.select (sox, [], [])
			if self.cli in rsox:
				req = self.cli.recv (1024)
				if req == '':
					more = False
				reqbuf = reqbuf + req
				(lines,reqbuf) = irctext2lines (reqbuf)
				for req in lines:
					if req == '':
						continue
					self.handle_upload (ircline2words (req))
			if self.srv in rsox:
				rsp = self.srv.recv (1024)
				if rsp == '':
					more = False
				rspbuf = rspbuf + rsp
				(lines,rspbuf) = irctext2lines (rspbuf)
				for rsp in lines:
					if rsp == '':
						continue
					self.handle_download (ircline2words (rsp))
		print 'Disconnected'



class IRCServer (SocketServer.TCPServer):
	address_family = socket.AF_INET6



#
# Setup the IRC server, bind to ircproxy and connect to ircserver
#

print 'SORRY -- THIS DEMO IS NOT WORKING YET'

retry = time.time () + 60
srv = None
while True:
	try:
		srv = IRCServer (ircproxy, IRCHandler)
		print 'Connections welcomed'
		srv.serve_forever ()
	except IOError, ioe:
		if time.time () < retry:
			if ioe.errno in [48, 98]:
				sys.stdout.write ('Found socket locked...')
				sys.stdout.flush ()
				time.sleep (5)
				sys.stdout.write (' retrying\n')
				sys.stdout.flush ()
				continue
		raise
	break
if srv:
	srv.server_close ()


