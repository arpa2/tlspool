/* This is the specifics module for SWIG mapping to Python.
 * It includes generic definitions from ../swig-tlspool.i
 *
 * This separation enables us to override function names, for instance
 * to raw/internal names, and then to add language-specific wrappers.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

%module tlspool


/* Renames, prefixing "_" when wrapped below for better parameter handling
 */
%rename(_pid) tlspool_pid;
%rename(_open_poolhandle) tlspool_open_poolhandle;
%rename(_ping) tlspool_ping;
%rename(_starttls) tlspool_starttls;
%rename(_control_detach) tlspool_control_detach;
%rename(_control_reattach) tlspool_control_reattach;
%rename(_prng) tlspool_prng;


// type maps to translate between SWIG's abstract data types and Python types

%typemap(in) ctlkey_t {
	ssize_t inlen = 0;
	if ((PyString_AsStringAndSize ($input, (char **) &($1), &inlen) == -1) || (inlen != TLSPOOL_CTLKEYLEN)) {
		PyErr_SetString (PyExc_ValueError, "Control keys are binary strings of length 16");
		return NULL;
	}
}

%typemap(out) ctlkey_t {
	if ($1 == NULL) {
		$result = Py_None;
	} else {
		$result = PyString_FromStringAndSize ($1, TLSPOOL_CTLKEYLEN);
	}
}


// apply the settings above as modifiers to the generic TLS Pool wrapping

%include "../swig-tlspool.i"


// helper function to raise OSError with the parameter set to C-reachable errno

%nothread raise_errno;

%inline %{

PyObject *raise_errno (void) {
	return PyErr_SetFromErrno (PyExc_OSError);
}

%}



// full-blown Python code to include

%pythoncode %{


import os
import socket

if not 'IPPROTO_SCTP' in dir (socket):
	socket.IPPROTO_SCTP = 132


def pid (pidfile=None):
	"""This function returns the process identity of the TLS Pool.
	   When no pidfile is provided, the default path as configured in the
	   TLS Pool libary will be used.  An Exception is thrown when there is
	   no TLS Pool.
	"""
	process_id = _pid (pidfile)
	if process_id < 0:
		_tlspool.raise_errno ()
	else:
		return process_id

def open_poolhandle (path=None):
	"""This function returns the OS-specific socket handle value for the
	   TLS Pool.  It is already connected, and shared with the internal
	   management of this module, so it must not be closed by the caller.
	   When no path is provided, the default path is used instead.
	   This function blocks until a connection to the TLS Pool succeeds.
	   The path is only used in the first call, and only when no prior
	   contact to the TLS Pool has been made; if that has happened, then
	   this function returns the previously found socket handle.
	"""
	fd = _open_poolhandle (path)
	if fd < 0:
		_tlspool.raise_errno ()
	else:
		return fd

def ping (YYYYMMDD_producer=_tlspool.TLSPOOL_IDENTITY_V2,
			facilities=_tlspool.PIOF_FACILITY_ALL_CURRENT):
	"""This function takes in a string with a date in YYYYMMDD format, followed
	   by a user@domain producer identifier.  It takes in an integer value
	   that is the logical or of PIOF_FACILITY_xxx values.  This is sent to
	   the TLS Pool through tlspool_ping() and the response is returned as a
	   similar tuple (YYYYMMDD_producer, facilities) as returned by the
	   TLS Pool.  This function blocks until a connection to the TLS Pool has
	   been found.  It is a good first command to send to the TLS Pool.
	"""
	pp = ping_data ()
	pp.YYYYMMDD_producer = YYYYMMDD_producer
	pp.facilities = facilities
	if _ping (pp) < 0:
		_tlspool.raise_errno ()
	else:
		return (pp.YYYYMMDD_producer, pp.facilities)

def make_tlsdata (localid='', remoteid='',
		flags=0, local_flags=0,
		ipproto=socket.IPPROTO_TCP, streamid=0, service='',
		timeout=0, ctlkey='TODOTODOTODOTODO'):
	"""Make a new tlsdata structure, based the fields that may be supplied
	   as flags, or otherwise as defaults.  Note that the field "local" is
	   renamed to "local_flags" for reasons of clarity.  This helper function
	   returns a tlsdata structure or raises an exception.
	"""
	tlsdata = starttls_data ()
	if ctlkey is not None:
		tlsdata.ctlkey = ctlkey
	tlsdata.service = service
	tlsdata.localid = localid
	tlsdata.remoteid = remoteid
	tlsdata.flags = flags
	tlsdata.local = local_flags
	tlsdata.ipproto = ipproto
	tlsdata.streamid = streamid
	tlsdata.timeout = timeout
	return tlsdata

class Connection:
	"""The tlspool.Connection class wraps around a connection to be protected
	   by the TLS Pool.  It uses the global socket for attaching to the
	   TLS Pool, but the individual instances of this class do represent
	   individual connections managed by the TLS Pool.
	   New instances can already collect a large number of parameters
	   that end up in the tlsdata structure of tlspool_starttls(),
	   but these values may also be created through getters/setters.
	   Some values have reasonable defaults, but some must have been
	   set before invoking the starttls() method on the instance.
	   The tlsdata fields all have defaults, as specified under
	   tlspool.make_tlsdata().
	"""

	def __init__ (self, cryptsocket, plainsocket=None, **tlsdata):
		self.cryptsk = cryptsocket
		self.cryptfd = cryptsocket.fileno ()
		self.plainsk = plainsocket
		self.plainfd = plainsocket.fileno () if plainsocket else -1
		self.tlsdata = make_tlsdata (**tlsdata)

	def close (self):
		assert (self.plainsk is not None)
		assert (self.plainfd >= 0)
		self.plainsk.close ()
		self.plainsk = None
		self.plainfd = -1

	def tlsdata_get (self, tlsvar):
		return self.tlsdata [tlsvar]

	def tlsdata_set (self, tlsvar, value):
		self.tlsdata [tlsvar] = value

	def starttls (self):
		"""Initiate a TLS connection with the current settings, as
		   provided during instantiation or through getter/setter
		   access afterwards.  The variables that are required at
		   this point are service and, already obliged when making
		   a new instance, cryptfd.
		"""
		assert (self.cryptsk is not None)
		assert (self.cryptfd >= 0)
		assert (self.tlsdata.service != '')
		try:
			af = self.cryptsk.family
		except:
			af = socket.AF_INET
		try:
			if   self.cryptsk.proto in [socket.IPPROTO_UDP]:
				socktp = socket.SOCK_DGRAM
			elif self.cryptsk.proto in [socket.IPPROTO_SCTP]:
				socktp = socket.SOCK_SEQPACKET
			else:
				socktp = socket.SOCK_STREAM
		except:
			socktp = socket.SOCK_STREAM
		plainsockptr = socket_data ()
		plainsockptr.unix_socket = self.plainfd
		# Provide None for the callback function, SWIG won't support it
		# We might at some point desire a library of C routine options?
		rv = _starttls (self.cryptfd, self.tlsdata, plainsockptr, None)
		self.plainfd = -1
		self.cryptfd = -1
		self.cryptsk = None
		if rv < 0:
			_tlspool.raise_errno ()
		if self.plainsk is None:
			self.plainfd = plainsockptr.unix_socket
			self.plainsk = socket.fromfd (self.plainfd, af, socktp)
		return self.plainsk

	def prng (self, length, label, ctxvalue=None):
		"""Produce length bytes of randomness from the master key, after
		   mixing it with the label and optional context value in ctxvalue.
		   The procedure has been described in RFC 5705.
		   #TODO# Find a way to return the random bytes, and use the length
		"""
		assert (length > 0)
		assert (1 <= len (label) <= 254)
		assert (1 <= len (ctxvalue or 'X') <= 254)
		buf = prng_data ()
		# buf.in1_len = len (label)
		# buf.in2_len = len (ctxvalue) if ctxvalue is not None else 255
		# buf.prng_len = length
		rv = _prng (label, ctxvalue, length, buf.buffer, self.tlsdata.ctlkey)
		if rv < 0:
			_tlspool.raise_errno ()
		else:
			return buf.buffer [:length]

	def control_detach (self):
		"""Detach control of this connection.  Although the connection
		   itself will still be available, control over it is diminished
		   and its continuation is no longer dependent on the current
		   connection.  You may need to pass tlsdata.ctlkey to another
		   process, or use control_reattach(), before this is reversed
		   in this process or another.
		"""
		_control_detach (self.tlsdata.ctlkey)

	def control_reattach (self, ctlkey=None):
		"""Reattach control of this connection.  The connection may have
		   called control_detach() in this process or another.  To help
		   with the latter case, its tlsdata.ctlkey must have been moved
		   into this instance.
		"""
		_control_reattach (self.tlsdata.ctlkey)

class SecurityMixIn:
	"""The SecurityMixIn class can be added as a subclass before a
	   (subclass of) SocketServer.BaseServer and it adds the facilities
	   of starttls(), startgss() and startssh() which add security through
	   one of the mechanisms.  In addition, have_xxx() can be used to
	   query in advance if startxxx() should be doable with the present
	   combination of TLS Pool and client code.
	   
	   Set a tlsdata field in the subclass, using the tlspool.make_tlsdata()
	   helper function, to bootstrap the same kind of behaviour on all
	   clients for which this class will be instantiated.  Such a tlsdata
	   class variable will automatically be cloned into instances.
	   Example code:
	   
		from tlspool import SecurityMixIn
		from SocketServer import BaseHandler
		
		class MyHandler (SecurityMixIn, BaseHandler):
			
			tlsdata = make_tlsdata (service=...)
			
			def handle (self):
				...
				self.starttls ()
			
			def handle_secure (self):
				...
	   
	   Alternatively, you can setup the tlsdata structure, or any part of it,
	   at a later time, through the tlsdata variable that will then be
	   instantiated during object initialisation.  Any such changes to fields
	   must be completed before invoking starttls() on this object.
	"""

	_pingdata = None
	tlsdata = None

	def __init__ (self):
		if self.tlsdata is None:
			self.tlsdata = make_tlsdata ()

	def have_tls (self):
		"""Check whether STARTTLS is supported on the current TLS Pool"""
		if self._pingdata is None:
			self._pingdata = ping ()
		return (self._pingdata [1] & PIOF_FACILITY_STARTTLS) != 0

	def have_ssh (self):
		"""Check whether STARTSSH is supported on the current TLS Pool"""
		if self._pingdata is None:
			self._pingdata = ping ()
		return (self._pingdata [1] & PIOF_FACILITY_STARTSSH) != 0

	def have_gss (self):
		"""Check whether STARTGSS is supported on the current TLS Pool"""
		if self._pingdata is None:
			self._pingdata = ping ()
		return (self._pingdata [1] & PIOF_FACILITY_STARTGSS) != 0

	def starttls (self):
		"""Modify the current socket to make it a TLS socket.  Use the
		   tlsdata as currently setup (see class-level documentation).
		   Afterwards, call handle_secure() to start from scratch with
		   a secure connection.  Also see the man page on the underlying
		   C library call, tlspool_starttls(3).
		   
		   Some protocols start TLS immediately, for instance HTTPS;
		   for such protocols, the handle() method would immediately
		   call starttls() and the actual handler code would move
		   into secure_handle().
		   
		   Other protocols, such as XMPP and IMAP, start in plaintext
		   and exchange pleasantries until they agree on running TLS.
		   This is the point where starttls() can be invoked.
		   
		   The methods startssh() and startgss() are place holders for
		   future alternatives to start other security wrappers than
		   TLS, after negotiating them in a manner similar to STARTTLS.
		"""
		if type (self.request) == tuple:
			sox = self.request [1]
		else:
			sox = self.request
		assert (type (sox) == socket._socketobject)
		try:
			af = sox.family
		except:
			af = socket.AF_INET
		try:
			if   sox.proto in [socket.IPPROTO_UDP]:
				socktp = socket.SOCK_DGRAM
			elif sox.proto in [socket.IPPROTO_SCTP]:
				socktp = socket.SOCK_SEQPACKET
			else:
				socktp = socket.SOCK_STREAM
		except:
			socktp = socket.SOCK_STREAM
		plainsockptr = socket_data ()
		plainsockptr.unix_socket = -1
		rv = _starttls (sox.fileno (), self.tlsdata, plainsockptr, None)
		if rv < 0:
			_tlspool.raise_errno ()
		assert (plainsockptr.unix_socket >= 0)
		sox2 = socket.fromfd (plainsockptr.unix_socket, af, socktp)
		if type (self.request) == tuple:
			self.request [1] = sox2
		else:
			self.request     = sox2
		self.handle_secure ()
		sox2.close ()

	def startssh (self):
		raise NotImplementedError ("Python wrapper does not implement STARTSSH")

	def startgss (self):
		raise NotImplementedError ("Python wrapper does not implement STARTGSS")

	def handle (self):
		"""When not overridden, the handle() method replaces the one in
		   later-mentioned classes in the inheritance structure.  This
		   means that this is the default behaviour when the SecureMixIn
		   precedes the handler class.  This particular version of handle()
		   does nothing but invoke starttls(), which in turn invokes
		   handle_secure() after the TLS handshake has succeeded.
		"""
		self.starttls ()

	def handle_secure (self):
		"""This method may be overridden to handle the secure part of the
		   connection, after starttls() has been called from within
		   handle().  This function is special in the sense that it may
		   refer to self.tlsdata and rely on the localid and remoteid
		   as being negotiated over TLS.
		   
		   Since any prior actions in handle() are usually unauthenticated,
		   it is common to start from scratch with the protocol.  The secure
		   layer however, tends to enable more features, such as blunt
		   password submission and, perhaps, privileged operations available
		   to the authenticated self.tlsdata.remoteid user.
		   
		   As an example, if the handler class is BaseHTTPRequestHandler,
		   its handle() method could be invoked on the secured content
		   (possibly after authorisation) with an override as follows:
		   
			def handle_secure (self):
				BaseHTTPRequestHandler.handle (self)
		"""
		pass

%}

%include "defines.h"
