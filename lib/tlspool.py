# tlspool.py -- Library functions for talking to the TLS Pool
#
# The functions below have been designed for Python 3.3+, which introduces
# socket.sendmsg() as well as socket.SOL_SOCKET and socket.SCM_RIGHTS
# support.  For older versions, an external package "fdsend" must be
# installed in its place.  Note that "fdsend" is licensed under GPLv2.
# (By the way, the normal "socket" module is named "syssocket" in this
# module, to make way for a tlspool.socket() function defined below.)
#
# NOTE: This library is currently not supportive of concurrent processes;
#       the tlspool.starttls function is not re-entrant.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import socket as syssocket
import struct
import array
import syslog
import random


PIOC_SUCCESS_V2           = 0x00000000
PIOC_ERROR_V2             = 0x00000001
PIOC_PING_V2		  = 0x00000010
PIOC_STARTTLS_V2	  = 0x00000024
PIOC_PLAINTEXT_CONNECT_V2 = 0x0000002a


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


def socket (path='/var/run/tlspool.sock'):
	"""This function returns a file descriptor for the TLS Pool, that
	   will be globally shared.  This is used internally by functions
	   that connect to the TLS Pool.  When a path is provided on its
	   first invocation, the TLS Pool may be accessed from another
	   location than the default.  TODO: This function checks if the
	   TLS Pool file descriptor is usable; if not, the function
	   continues as though it was called for the first time, and
	   reconnects.
	"""
	global poolfd
	#TODO# Check if the poolfd is usable, otherwise close and set -1
	if poolfd == -1:
		newfd = syssocket.socket (syssocket.AF_UNIX, syssocket.SOCK_STREAM, 0)
		if path is None:
			path='/var/run/tlspool.sock'
		newfd.connect (path)
		poolfd = newfd
	return poolfd


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
			'ctlkey': struct.pack ('16B',
					*prng.sample (xrange (256), 16)),
			'service': '',
			'timeout': 0,
		}
		for (k,v) in tlsdefaults.items ():
			if not tlsdata.has_key (k):
				tlsdata [k] = v
		cmd = struct.pack ('HHI' + 'IIBH128s128s16B32sI', 
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
				) = struct.unpack ('HHI' + 'IIBH128s128s16B32sI', msg [:328])
			if cmdcode == PIOC_ERROR_V2:
				(reqid, cbid, cmdcode,
					tlserrno,
					message
					) = struct.unpack ('HHI' + 'I128s', msg [:140])
				message = message.split ('\x00') [0]
				syslog.syslog (syslog.LOG_INFO, 'TLS Pool error to _starttls_libfun(): ' + message)
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
				cmd = struct.pack ('HHI' + 'IIBH128s128s', 
							reqid, cbid, cmdcode,
							tlsdata ['flags'],
							tlsdata ['localflags'],
							tlsdata ['ipproto'],
							tlsdata ['stream'],
							tlsdata ['localid'],
							tlsdata ['remoteid'])
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



