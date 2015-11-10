# tlspool.py -- Library functions for talking to the TLS Pool
#
# The functions below have been designed for Python 3.3+, which introduces
# socket.sendmsg() as well as socket.SOL_SOCKET and socket.SCM_RIGHTS
# support.  For older versions, an external package "fdsend" must be
# installed in its place.  Note that "fdsend" is licensed under GPLv2.
# (By the way, the normal "socket" module is named "syssocket" in this
# module, to make way for a tlspool.socket() function defined below.)
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import socket as syssocket
import string
import struct
import array
import syslog
import random
import threading


TLSPOOL_IDENTITY_TMP	= '20150824tlspool@tmp.vanrein.org'


PIOC_SUCCESS_V2           = 0x00000000
PIOC_ERROR_V2             = 0x00000001
PIOC_PING_V1		  = 0x00000010
PIOC_STARTTLS_V2	  = 0x00000024
PIOC_STARTTLS_LOCALID_V2  = 0x00000028
PIOC_PINENTRY_V1	  = 0x00000029
PIOC_PLAINTEXT_CONNECT_V2 = 0x0000002a
PIOC_STARTTLS_PRNG_V2	  = 0x0000002b
PIOC_CONTROL_DETACH_V2	  = 0x00000100
PIOC_CONTROL_REATTACH_V2  = 0x00000101
PIOC_LIDENTRY_REGISTER_V2 = 0x00000200
PIOC_LIDENTRY_CALLBACK_V2 = 0x00000201

PIOC_LOCAL		  = 0x80000000


PIOF_STARTTLS_LOCALROLE_CLIENT		= 0x00000001
PIOF_STARTTLS_LOCALROLE_SERVER		= 0x00000002
PIOF_STARTTLS_LOCALROLE_PEER		= 0x00000003

PIOF_STARTTLS_REMOTEROLE_CLIENT		= 0x00000004
PIOF_STARTTLS_REMOTEROLE_SERVER		= 0x00000008
PIOF_STARTTLS_REMOTEROLE_PEER		= 0x0000000c

PIOF_STARTTLS_WITHOUT_SNI		= 0x00000200

PIOF_STARTTLS_DETACH			= 0x00002000
# PIOF_STARTTLS_FORK			= 0x00004000
PIOF_STARTTLS_DOMAIN_REPRESENTS_USER	= 0x00008000
PIOF_STARTTLS_LOCALID_CHECK		= 0x00010000

PIOF_LIDENTRY_SKIP_DBENTRY		= 0x00000080	# in all _SKIP_
PIOF_LIDENTRY_SKIP_USER			= 0x00000081
PIOF_LIDENTRY_SKIP_DOMAIN_SAME		= 0x00000082
PIOF_LIDENTRY_SKIP_DOMAIN_ONEUP		= 0x00000084
PIOF_LIDENTRY_SKIP_DOMAIN_SUB		= 0x00000086	# _SAME | _ONEUP
PIOF_LIDENTRY_SKIP_NOTROOT		= 0x00000088

PIOF_LIDENTRY_DBENTRY			= 0x00000100
PIOF_LIDENTRY_DBINSERT			= 0x00000200
PIOF_LIDENTRY_DBAPPEND			= 0x00000400
PIOF_LIDENTRY_DBREORDER			= 0x00000800
# PIOF_LIDENTRY_NEW = 0x00010000
# PIOF_LIDENTRY_ONTHEFLY = 0x00030000


# Global variable shared by all callers
poolfd = -1


# The pseudo-random number generator
prng = random.Random ()

if sys.version_info [:2] < (3,3):
	try:
		# Import the fdsend package to support ancilary data sending
		# as a fallback for full Python 3.3+ support.
		#
		# Note: This package is licensed under GPLv2, so either your
		#       user installs it or your software becomes GPLv2.
		import fdsend
	except:
		raise ImportError ('"import tlspool" requires python >= 3.3 or the fdsend package\n')
	def _stub_sendmsg (self, buffers, ancdata=None, flags=0):
		"""Stub sendmsg() function, implementing just enough of the
		   Python 3.3 syssocket.sendmsg() to work for the TLS Pool
		"""
		fds = []
		if ancdata is not None:
			assert (len (ancdata) == 1)
			assert (len (ancdata [0]) == 3)
			assert (ancdata [0][:2] == (syssocket.SOL_SOCKET,syssocket.SCM_RIGHTS))
			fdsarr = ancdata [0][2]
			while len (fdsarr) > 0:
				fds.append (fdsarr.pop (0))
		fdsend.sendfds (self.fileno (), ''.join (buffers), flags=flags, fds=fds)
	def _stub_recvmsg (self, bufsize, ancbufsize=0, flags=0):
		"""Stub recvmsg() function, implementing just enough of the
		   Python 3.3 syssocket.recvmsg() to work for the TLS Pool
		"""
		(msg,anc) = fdsend.recvfds (self.fileno (), 1025, flags=flags, numfds=1)
		if anc is None:
			anc = []
		ancdata = [(syssocket.SOL_SOCKET, syssocket.SCM_RIGHTS, passfd) for passfd in anc]
		return ([msg], ancdata, None, None)
	def _stub_CMSG_SPACE (self, ):
		"""Stub CMSG_SPACE() function in preparation of Python 3.3,
		   just enough to work for the TLS Pool.
		"""
		return 100
	def _stub_CMSG_LEN (self, ):
		"""Stub CMSG_LEN() function in preparation of Python 3.3,
		   just enough to work for the TLS Pool.
		"""
		return 100
	# Patch syssocket and its objects with the stub functions
	syssocket.SOL_SOCKET = 1
	syssocket.SCM_RIGHTS = 0x01
	syssocket._socketobject.sendmsg    = _stub_sendmsg
	syssocket._socketobject.recvmsg    = _stub_recvmsg
	syssocket._socketobject.CMSG_SPACE = _stub_CMSG_SPACE
	syssocket._socketobject.CMSG_LEN   = _stub_CMSG_LEN  

threadlocals = threading.local ()

def socket (path='/var/run/tlspool.sock'):
	"""This function returns a file descriptor for the TLS Pool, that
	   will be globally shared.  This is used internally by functions
	   that connect to the TLS Pool.  When a path is provided on its
	   first invocation, the TLS Pool may be accessed from another
	   location than the default.  TODO: This function checks if the
	   TLS Pool file descriptor is usable; if not, the function
	   continues as though it was called for the first time, and
	   reconnects.
	""" """
	   Unlike the C library function, this call opens a new connection
	   to the TLS Pool for every thread.  This is a coding simplification
	   and may need to be repaired if it conflicts with scalability.
	   For now, the assumption is that Python code is not written to scale.
	"""
	poolfd = getattr (threadlocals, 'poolfd', -1)
	#TODO# Check if the poolfd is usable, otherwise close and set -1
	if poolfd == -1:
		newfd = syssocket.socket (syssocket.AF_UNIX, syssocket.SOCK_STREAM, 0)
		if path is None:
			path='/var/run/tlspool.sock'
		newfd.connect (path)
		threadlocals.poolfd = newfd
		poolfd = newfd
	return poolfd


def ping (my_id_str):
	"""Send the my_id_str to the TLS Pool, and return its result string.
	""" """
	   When an error occurs, None is returned instead of the ping reply.
	"""
	pfd = socket (None)
	try:
		cmd = struct.pack ('HHI' + '136s', 
					01234, 0, PIOC_PING_V1,
					my_id_str
				)
		cmd = struct.pack ('376s', cmd)
		pfd.sendmsg ([cmd])
		([msg], _, _, _) = pfd.recvmsg (376)
		(reqid, cbid, cmdcode2,
			ping_resp_str
			) = struct.unpack ('HHI' + '136s', msg [:144])
		if cmdcode2 == PIOC_ERROR_V2:
			(reqid, cbid, cmdcode2,
				tlserrno,
				message
				) = struct.unpack ('HHI' + 'I128s', msg [:140])
			message = message.split ('\x00') [0]
			syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.ping(): ' + message)
			raise Exception ()
		elif cmdcode2 == PIOC_PING_V1:
			return ping_resp_str.split ('\x00') [0]
		else:
			syslog.syslog (syslog.LOG_ERR, 'Invalid response to tlspool.ping()')
			raise Exception ()
	except Exception, e:
		return None


def starttls (cryptfd, tlsdata, privdata, namedconnect=None):
	"""The library function for starttls, which is normally called through
	   one of the two wrappers below, which start client and server sides.
	   """ """
	   The cryptfd handle supplies the TLS connection that is assumed to have
	   been setup.  When the function ends, either in success or failure, this
	   handle will no longer be available to the caller; the responsibility of
	   closing it is passed on to the function and/or the TLS Pool.
	   """ """
	   The tlsdata structure will be copied into the command structure,
	   and upon completion it will be copied back.  You can use it to
	   communicate flags, protocols and other parameters, including the
	   most important settings -- local and remote identifiers.  See
	   the socket protocol document for details.
	   """ """
	   The privdata handle is used in conjunction with the namedconnect() call;
	   it is passed on to connect the latter to the context from which it was
	   called and is not further acted upon by this function.
	   """ """
	   The namedconnect() function is called when the identities have been
	   exchanged, and established, in the TLS handshake.  This is the point
	   at which a connection to the plaintext side is needed, and a callback
	   to namedconnect() is made to find a handle for it.  The function is
	   called with a version of the tlsdata that has been updated by the
	   TLS Pool to hold the local and remote identities.  The return value
	   should be -1 on error, with errno set, or it should be a valid file
	   handle that can be passed back to the TLS Pool to connect to.
	   """ """
	   When the namedconnect argument passed is NULL, default behaviour is
	   triggered.  This interprets the privdata handle as an (int *) holding
	   a file descriptor.  If its value is valid, that is, >= 0, it will be
	   returned directly; otherwise, a socketpair is constructed, one of the
	   sockets is stored in privdata for use by the caller and the other is
	   returned as the connected file descriptor for use by the TLS Pool.
	   This means that the privdata must be properly initialised for this
	   use, with either -1 (to create a socketpair) or the TLS Pool's
	   plaintext file descriptor endpoint.  The file handle returned in
	   privdata, if it is >= 0, should be closed by the caller, both in case
	   of success and failure.
	   """ """
	   This function returns zero on success, and -1 on failure.  In case of
	   failure, errno will be set.
	"""
	pfd = socket (None)
	sentfd = -1
	try:
		cmdcode = PIOC_STARTTLS_V2
		tlsdefaults = {
			'localid': '',
			'remoteid': '',
			'flags': 0x00000209,	# local=client, remote=server, SNI
			'localflags': 0x00000000,
			'ipproto': syssocket.IPPROTO_TCP,
			'stream': 0,
			'ctlkey': struct.pack ('16s',
					string.join ( [chr (c) for c in
						prng.sample (xrange (256), 16) ],
						'')
					),
			'service': '',
			'timeout': 0,
		}
		for (k,v) in tlsdefaults.items ():
			if not tlsdata.has_key (k):
				tlsdata [k] = v
		cmd = struct.pack ('HHI' + 'IIBH128s128s16s32sI', 
					12345, 0, cmdcode,
					tlsdata ['flags'],
					tlsdata ['localflags'],
					tlsdata ['ipproto'],
					tlsdata ['stream'],
					tlsdata ['localid'],
					tlsdata ['remoteid'],
					tlsdata ['ctlkey'],
					tlsdata ['service'],
					tlsdata ['timeout'])
		cmd = struct.pack ('376s', cmd)
		anc = [ (syssocket.SOL_SOCKET,
			 syssocket.SCM_RIGHTS,
			 array.array ("i", [cryptfd.fileno()])) ]
		sentfd = cryptfd
		pfd.sendmsg ([cmd], anc)
		processing = True
		while processing:
			([msg], _, _, _) = pfd.recvmsg (376)
			(reqid, cbid, cmdcode,
				tlsdata ['flags'],
				tlsdata ['localflags'],
				tlsdata ['ipproto'],
				tlsdata ['stream'],
				tlsdata ['localid'],
				tlsdata ['remoteid'],
				tlsdata ['ctlkey'],
				tlsdata ['service'],
				tlsdata ['timeout']
			) = struct.unpack ('HHI' + 'IIBH128s128s16s32sI', msg [:328])
			if cmdcode == PIOC_ERROR_V2:
				(reqid, cbid, cmdcode,
					tlserrno,
					message
					) = struct.unpack ('HHI' + 'I128s', msg [:140])
				message = message.split ('\x00') [0]
				syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.starttls(): ' + message)
				raise Exception ()
			elif cmdcode == PIOC_PLAINTEXT_CONNECT_V2:
				if namedconnect is not None:
					plainfd = namedconnect (tlsdata, privdata)
				else:
					# Default namedconnect() implementation
					if privdata.has_key ('plainfd'):
						plainfd = privdata ['plainfd']
					else:
						plainfd = -1
					if plainfd < 0:
						(plainfd, privdata ['plainfd']) = syssocket.socketpair ()
						#TODO# Failure => reply error
				# We now have a value to send in plainfd
				cmd = struct.pack ('HHI' + 'IIBH128s128s16s32sI', 
							reqid, cbid, cmdcode,
							tlsdata ['flags'],
							tlsdata ['localflags'],
							tlsdata ['ipproto'],
							tlsdata ['stream'],
							tlsdata ['localid'],
							tlsdata ['remoteid'],
							tlsdata ['ctlkey'],
							tlsdata ['service'],
							tlsdata ['timeout']
						)
				cmd = struct.pack ('376s', cmd)
				anc = [ (syssocket.SOL_SOCKET,
					 syssocket.SCM_RIGHTS,
					 array.array ("i", [plainfd.fileno()])) ]
				if sentfd >= 0:
					sentfd.close ()
				sentfd = plainfd
				pfd.sendmsg ([cmd], anc)
			elif cmdcode == PIOC_STARTTLS_V2:
				# Whee, we're done!
				processing = 0
			else:
				raise Exception ()
		return 0
	except Exception, e:
		return -1
	finally:
		if sentfd != -1:
			sentfd.close ()


def starttls_prng (ctlkey, reqlen=350, label='EXPERIMENTAL-DEFAULT', context=None):
	"""The library function to run a PRNG based on the master key.  The two
	   endpoints will find the same random material when they provide the same
	   label and optional context parameters.  The resulting random material
	   is protected by the process that led to the master key, so it inherits
	   properties such as Forward Secrecy.
	   """ """
	   Set ctlkey to the control key for the connection, reqlen to the requested
	   number of bytes, label and context as desired by the application; note
	   that the label is subject to registration with IANA, but that anything
	   starting with 'EXPERIMENTAL' is welcomed.  TLS Pool validates these
	   strings to comply.  For details, see RFC 5705.
	   """ """
	   This function returns a string of (at least) reqlen PRNG bytes on
	   success, or None to signal an error condition.  Please take note that
	   a garbage-collected environment such as Python's may leak these
	   bytes in many memory locations, making the outcome less suitable for
	   security keys.  Please use the C API for any real work in this area.
	"""
	assert (len (ctlkey) == 16)
	assert (len (label) <= 255)
	assert (context is None or len (context) <= 255)
	buf = ctlkey + label + (context if context else '')
	assert (len (buf) <= 350)
	buf = buf + chr (0x00) * (350 - len (buf))	# Fillup to 350 bytes
	pfd = socket (None)
	try:
		cmdcode = PIOC_STARTTLS_PRNG_V2;
		cmd = struct.pack ('HHI' + 'hhh350s', 
					56789, 0, cmdcode,
					len (label),
					len (context) if context else -1,
					reqlen,
					buf
				)
		cmd = struct.pack ('376s', cmd)
		pfd.sendmsg ([cmd])
		([msg], _, _, _) = pfd.recvmsg (376)
		(reqid, cbid, cmdcode,
			_,
			_,
			gotlen,
			buf
			) = struct.unpack ('HHI' + 'HHH350s', msg [:364])
		if cmdcode == PIOC_ERROR_V2:
			(reqid, cbid, cmdcode,
				tlserrno,
				message
				) = struct.unpack ('HHI' + 'I128s', msg [:140])
			message = message.split ('\x00') [0]
			syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.starttls_prng(): ' + message)
			raise Exception ()
		elif cmdcode == PIOC_STARTTLS_PRNG_V2:
			if gotlen != reqlen:
				syslog.syslog (syslog.LOG_NOTICE, 'TLS Pool returned PRNG with %d bytes instead of %d' % (gotlen, reqlen))
				if gotlen < reqlen:
					raise Exception ()
			return buf [:gotlen]
	except Exception, e:
		# return None
		raise


def _control_xxtach (ctlkey, cmdcode, flags=0, name=''):
	"""Internal function to invoke a PIOC_CONTROL_ cmd and return True on
	   success, or False on error.
	"""
	assert (len (ctlkey) == 16)
	pfd = socket (None)
	try:
		cmd = struct.pack ('HHI' + 'I16s128s', 
					45678, 0, cmdcode,
					flags,
					ctlkey,
					name
				)
		cmd = struct.pack ('376s', cmd)
		pfd.sendmsg ([cmd])
		([msg], _, _, _) = pfd.recvmsg (376)
		(reqid, cbid, cmdcode2,
			flags,
			ctlkey,
			name
			) = struct.unpack ('HHI' + 'I16s128s', msg [:156])
		if cmdcode == PIOC_ERROR_V2:
			(reqid, cbid, cmdcode2,
				tlserrno,
				message
				) = struct.unpack ('HHI' + 'I128s', msg [:140])
			message = message.split ('\x00') [0]
			syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.control_detach/_reattach(): ' + message)
			raise Exception ()
		elif cmdcode2 == cmdcode:
			return True
	except Exception, e:
		return False


def control_detach (ctlkey):
	"""Detach the (currently attached) connection from the file descriptor that
	   connects to the TLS Pool.  As a result, no further control can be
	   exercised over the connection, but it also will not die when the
	   connection to the TLS Pool terminates.
	""" """
	   This function returns True on success, or False on error.
	"""
	_control_xxtach (ctlkey, PIOC_CONTROL_DETACH_V2)


def control_reattach (ctlkey):
	"""Reattach the (currently detached) connection to the file descriptor that
	   connects to the TLS Pool.  As a result, the connection can be further
	   controlled, but it will also die when the connection to the TLS Pool
	   terminates.
	""" """
	   This function returns True on success, or False on error.
	"""
	_control_xxtach (ctlkey, PIOC_CONTROL_REATTACH_V2)


def pinentry (pinentry_cb, flags_reg, timeout_usec=60000000):
	"""The library function for PIN entry, which is normally called from a
	   daemon that offers PIN entry popup windows.  This function
	   only returns in case of an error.  Otherwise, it forms a service loop
	   that invoked the pinentry_cb function with a dictionary holding all the
	   structure elements, and it expects a similar dictionary (possibly the
	   same one with adaptions) returned from the function.
	   """ """
	   The flags_reg and timeout_usec should be set as desired during
	   registration; the timeout indicates how quickly the pinentry_cb
	   function is supposed to return.  When in time, the claim on the
	   PIN entry facility will not have been lost to another process.
	"""
	pfd = socket (None)
	try:
		cmdcode = PIOC_PINENTRY_V1
		cmd = struct.pack ('HHI' + 'III128s128s33s17s17s33s', 
					23456, 0, cmdcode,
					flags_reg,
					0,		# not yet meaningful
					timeout_usec,
					'',		# not yet meaningful
					'',		# not yet meaningful
					' ' * 32,	# not yet meaningful
					' ' * 16,	# not yet meaningful
					' ' * 16,	# not yet meaningful
					' ' * 32	# not yet meaningful
				)
		cmd = struct.pack ('376s', cmd)
		pfd.sendmsg ([cmd])
		while True:
			([msg], _, _, _) = pfd.recvmsg (376)
			pinentry = { }
			(reqid, cbid, cmdcode,
				pinentry ['flags'],
				pinentry ['attempt'],
				pinentry ['timeout_us'],
				pinentry ['pin'],
				pinentry ['prompt'],
				pinentry ['token_manuf'],
				pinentry ['token_model'],
				pinentry ['token_serial'],
				pinentry ['token_label'],
				) = struct.unpack ('HHI' + 'III128s128s33s17s17s33s', msg [:376])
			for k in [	'token_manuf',
					'token_model',
					'token_serial',
					'token_label' ]:
				pinentry [k] = pinentry [k].split ('\x00') [0]
			if cmdcode == PIOC_ERROR_V2:
				(reqid, cbid, cmdcode,
					tlserrno,
					message
					) = struct.unpack ('HHI' + 'I128s', msg [:140])
				message = message.split ('\x00') [0]
				syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.pinentry(): ' + message)
				raise Exception ()
			elif cmdcode == PIOC_PINENTRY_V1:
				# We should invoke lidentry_cb
				pinentry ['pin'] = ''
				pinentry = pinentry_cb (pinentry)
				# We now have a value to send back
				for (k,l) in [	('token_manuf', 32),
						('token_model', 16),
						('token_serial', 16),
						('token_label', 32) ]:
					pinentry [k] = (pinentry [k] + ' ' * 32) [:l]
				cmd = struct.pack ('HHI' + 'III128s128s33s17s17s33s', 
							reqid, cbid, cmdcode,
							pinentry ['flags'],
							pinentry ['attempt'],
							pinentry ['timeout_us'],
							pinentry ['pin'],
							pinentry ['prompt'],
							pinentry ['token_manuf'],
							pinentry ['token_model'],
							pinentry ['token_serial'],
							pinentry ['token_label'],
						)
				pinentry ['pin'] = ''
				pfd.sendmsg ([cmd])
			else:
				raise Exception ()
		return 0
	except Exception, e:
		return -1


def lidentry (lidentry_cb, flags_reg, timeout_sec=60):
	"""The library function for localid entry, which is normally called from a
	   daemon that offers LID entry (or LID choice) services.  This function
	   only returns in case of an error.  Otherwise, it forms a service loop
	   that invoked the lidentry_cb function with a dictionary holding all the
	   structure elements plus a key "localids_db" holding all the database
	   entries found, and it expects a similar dictionary (possibly the
	   same one with adaptions) returned from the function.
	   """ """
	   The flags_reg and timeout_sec should be set as desired during
	   registration; the timeout indicates how quickly the lidentry_cb
	   function is supposed to return.  When in time, the claim on the
	   LID entry facility will not have been lost to another process.
	"""
	pfd = socket (None)
	try:
		cmdcode = PIOC_LIDENTRY_REGISTER_V2
		cmd = struct.pack ('HHI' + 'IHI128s128s', 
					34567, 0, cmdcode,
					flags_reg,
					0,	# not yet meaningful
					timeout_sec,
					'',	# not yet meaningful
					'',	# not yet meaningful
				)
		cmd = struct.pack ('376s', cmd)
		pfd.sendmsg ([cmd])
		localids_db = []
		while True:
			([msg], _, _, _) = pfd.recvmsg (376)
			lidentry = { }
			(reqid, cbid, cmdcode,
				lidentry ['flags'],
				lidentry ['maxlevels'],
				lidentry ['timeout'],
				lidentry ['localid'],
				lidentry ['remoteid']
				) = struct.unpack ('HHI' + 'IHI128s128s', msg [:270])
			if cmdcode == PIOC_ERROR_V2:
				(reqid, cbid, cmdcode,
					tlserrno,
					message
					) = struct.unpack ('HHI' + 'I128s', msg [:140])
				message = message.split ('\x00') [0]
				syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to tlspool.lidentry(): ' + message)
				raise Exception ()
			elif cmdcode == PIOC_LIDENTRY_CALLBACK_V2:
				if lidentry ['flags'] & PIOF_LIDENTRY_DBENTRY:
					# We received a database entry, pile it up
					localids_db.append (lidentry ['localid'])
				else:
					# We should invoke lidentry_cb
					lidentry ['localids_db'] = localids_db
					localids_db = []
					lidentry = lidentry_cb (lidentry)
				# We now have a value to send back
				cmd = struct.pack ('HHI' + 'IHI128s128s', 
							reqid, cbid, cmdcode,
							lidentry ['flags'],
							lidentry ['maxlevels'],
							lidentry ['timeout'],
							lidentry ['localid'],
							lidentry ['remoteid'])
				pfd.sendmsg ([cmd])
			else:
				raise Exception ()
		return 0
	except Exception, e:
		return -1



