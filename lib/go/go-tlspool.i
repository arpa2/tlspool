/* This is the specifics module for SWIG mapping to Go.
 * It includes generic definitions from ../swig-tlspool.i
 *
 * This separation enables us to override function names, for instance
 * to raw/internal names, and then to add language-specific wrappers.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */


%module tlspool


/* Renames, starting with lowercase when wrapped below; this hides names from export
 */
%rename(pid) tlspool_pid;
%rename(open_poolhandle) tlspool_open_poolhandle;
%rename(ping) tlspool_ping;
%rename(starttls) tlspool_starttls;
%rename(control_detach) tlspool_control_detach;
%rename(control_reattach) tlspool_control_reattach;
%rename(prng) tlspool_prng;


// type maps to translate between SWIG's abstract data types and Go types

// %typemap(in) ctlkey_t {
// 	ssize_t inlen = 0;
// 	if ((PyString_AsStringAndSize ($input, (char **) &($1), &inlen) == -1) || (inlen != TLSPOOL_CTLKEYLEN)) {
// 		PyErr_SetString (PyExc_ValueError, "Control keys are binary strings of length 16");
// 		return NULL;
// 	}
// }

// %typemap(out) ctlkey_t {
// 	if ($result == NULL) {
// 		$1 = Py_None;
// 	} else {
// 		$1 = PyString_FromStringAndSize ($result, TLSPOOL_CTLKEYLEN);
// 	}
// }


// apply the settings above as modifiers to the generic TLS Pool wrapping

%include "../swig-tlspool.i"


// helper function to raise OSError with the parameter set to C-reachable errno

// %inline %{
// 
// PyObject *raise_errno (void) {
// 	return PyErr_SetFromErrno (PyExc_OSError);
// }
// 
// %}



// full-blown Go code to include

%go_import ("syscall")

%insert(go_wrapper) %{


// Connection objects represent a single (network) connection being protected
// through the TLS Pool.  It is constructed with NewConnection() and deleted
// with DeleteConnection().  During its life, parameters will be setup in it,
// and then a call to its StartTLS() method initiates the TLS handshake.
type Connection struct {
	TLSdata Starttls_data
	cryptsock int
	plainsock int
	ctlkey ctlkey_t
}

// Pid() returns the process identity of the TLS Pool.  When no pidfile is
// provided, the default path as configured in the TLS Pool library will be used.
// When no TLS Pool is found, ok returns 0.
func Pid (pidfile *string) (pid int, ok int) {
	pid := pid (pidfile)
	if pid < 0 {
		return -1, 0
	}
	return pid, 1
}


// OpenPoolHandle() returns a handle to the TLS Pool.  If no connection has been
// made to the TLS Pool yet, it will try to open it at the given path, or else
// at the default path.
func OpenPoolHandle (path *string) (int handle, int ok) {
	hdl := open_poolhandle (string)
	if hdl < 0 {
		return -1, 0
	}
	return hdl, 1
}


// Ping() ensures that it is connected to the TLS Pool, and exchanges
// a number of parameters, such as API function and supported features.
// There is no need to have a Connection for this call.
// The function returns 0 in ok when something stopped it from working
//
func Ping (yyyymmdd_producer *string, facilities *uint) (ymdprod string, facil uint, ok int) {
	pingdata := NewPing_data ()
	defer DeletePing_data (pingdata)
	if yyyymmdd_producer == nil {
		yyyymmdd_producer = TLSPOOL_IDENTITY_V2
	}
	if facilities == nil {
		facilities = PIOF_FACILITY_ALL_CURRENT
	}
	pingdata.SetYYYYMMDD_producer (yyyymmdd_producer)
	pingdata.SetFacilities (facilities)
	if ping (pingdata) != 0 {
		return "", 0, 0
	}
	return pingdata.GetYYYYMMDD_producer (), pingdata.GetFacilities (), 1
}

// NewConnection() returns a TLS connection to be managed by the TLS Pool.
// The structure contains a TLSdata structure, in which the customary
// settings need to be made before invoking starttls().
//
// Call this function with a file descriptor for the side that will be
// encrypted, for instance after just having accepted a connection or after
// a connection has gone through a STARTTLS command exchange.
//
// The returned Connection MUST be deleted with DeleteConnection at the
// end of its life; you MAY use defer to achieve that.
//
func NewConnection (cryptsock int) (cnx *Connection, ok int) {
	if cryptsock < 0 {
		return nil, 0
	}
	neo := new (Connection)
	neo.TLSdata = NewStarttls_data ()
	neo.cryptsock = cryptsock
	neo.plainsock = -1
	return neo, 1
}

// DeleteConnection() cleans up what has been created by NewConnection().
// This MUST be called when NewConnection succeeds, so as to avoid
// leaking memory by not decoupling the C backend structure.
//
func (cnx Connection) DeleteConnection () {
	if cnx.TLSdata != nil {
		DeleteStarttls_data (cnx.TLSdata)
	}
}

// StartTLS() uses the prepared information in a Connection to start TLS
// over the cryptsock that was provided to NewConnection().
//
func (cnx Connection) StartTLS (plainsock int) (ok int) {
	if cnx.plainsock < 0 {
		return 0
	}
	//TODO// Implement, instead of just scaring out and reporting error
	return 0
}

// PRNG() produces length bytes of randomness from the master key, after mixing
// it with the label and optional context value in ctxvalue.  The procedure has
// been described in RFC 5705.
func (cnx Connection) PRNG (length uint, label *byte, ctxvalue *byte) (random byte[], int ok) {
	if label == nil {
		return nil, 0
	}
	//TODO// or just call "func Prng()" in tlspool.go with its 5 params?!?
	prng := NewPrng_data ()
	defer DeletePrng_data (prng)
	buf := prng.GetBuffer ()
	if TLSPOOL_CTLKEYLEN + len (label) + len (ctxvalue) > len (buf) {
		return nil, 0
	}
	//TODO// write cnx.ctlkey
	prng.SetPrng_len (length)
	prng.SetIn1_len (len (label))
	//TODO// write cnx.label
	if ctxvalue != nil {
		prng.SetIn2_len (len (ctxvalue))
		//TODO// write cnx.ctxvalue
	} else {
		prng.SetIn2_len (-1)
	}
	rv := prng (label, ctxvalue, length, buf, cnx.ctlkey)
	if rv < 0 {
		return nil, 0
	}
	//TODO// Actually return the bytes up to length, as contained within buf
	return buf, 1
}

//	def __init__ (self, cryptsocket,
//					plainsocket=None,
//					ctlkey=None, 
//					localid='',
//					remoteid='',
//					flags=0,
//					local_flags=0,
//					ipproto=socket.IPPROTO_TCP,
//					streamid=0,
//					service='',
//					timeout=0):

%}

//%pythoncode %{
//
//
//import os
//import socket
//
//if not 'IPPROTO_SCTP' in dir (socket):
//	socket.IPPROTO_SCTP = 132
//
//
//def pid (pidfile=None):
//	"""This function returns the process identity of the TLS Pool.
//	   When no pidfile is provided, the default path as configured in the
//	   TLS Pool libary will be used.  An Exception is thrown when there is
//	   no TLS Pool.
//	"""
//	process_id = _pid (pidfile)
//	if process_id < 0:
//		_tlspool.raise_errno ()
//	else:
//		return process_id
//
//def open_poolhandle (path=None):
//	"""This function returns the OS-specific socket handle value for the
//	   TLS Pool.  It is already connected, and shared with the internal
//	   management of this module, so it must not be closed by the caller.
//	   When no path is provided, the default path is used instead.
//	   This function blocks until a connection to the TLS Pool succeeds.
//	   The path is only used in the first call, and only when no prior
//	   contact to the TLS Pool has been made; if that has happened, then
//	   this function returns the previously found socket handle.
//	"""
//	fd = _open_poolhandle (path)
//	if fd < 0:
//		_tlspool.raise_errno ()
//	else:
//		return fd
//
//def ping (YYYYMMDD_producer=_tlspool.TLSPOOL_IDENTITY_V2,
//			facilities=_tlspool.PIOF_FACILITY_ALL_CURRENT):
//	"""This function takes in a string with a date in YYYYMMDD format, followed
//	   by a user@domain producer identifier.  It takes in an integer value
//	   that is the logical or of PIOF_FACILITY_xxx values.  This is sent to
//	   the TLS Pool through tlspool_ping() and the response is returned as a
//	   similar tuple (YYYYMMDD_producer, facilities) as returned by the
//	   TLS Pool.  This function blocks until a connection to the TLS Pool has
//	   been found.  It is a good first command to send to the TLS Pool.
//	"""
//	pp = ping_data ()
//	pp.YYYYMMDD_producer = YYYYMMDD_producer
//	pp.facilities = facilities
//	if _ping (pp) < 0:
//		_tlspool.raise_errno ()
//	else:
//		return (pp.YYYYMMDD_producer, pp.facilities)
//
//class Connection:
//	"""The tlspool.Connection class wraps around a connection to be protected
//	   by the TLS Pool.  It uses the global socket for attaching to the
//	   TLS Pool, but the individual instances of this class do represent
//	   individual connections managed by the TLS Pool.
//	   New instances can already collect a large number of parameters
//	   that end up in the tlsdata structure of tlspool_starttls(),
//	   but these values may also be created through getters/setters.
//	   Some values have reasonable defaults, but some must have been
//	   set before invoking the starttls() method on the instance.
//	"""
//
//	def __init__ (self, cryptsocket,
//					plainsocket=None,
//					ctlkey=None, 
//					localid='',
//					remoteid='',
//					flags=0,
//					local_flags=0,
//					ipproto=socket.IPPROTO_TCP,
//					streamid=0,
//					service='',
//					timeout=0):
//		self.cryptsk = cryptsocket
//		self.cryptfd = cryptsocket.fileno ()
//		self.plainsk = plainsocket
//		self.plainfd = plainsocket.fileno () if plainsocket else -1
//		self.tlsdata = starttls_data ()
//		self.ctlkey = ctlkey
//		self.tlsdata.service = service
//		self.tlsdata.localid = localid
//		self.tlsdata.remoteid = remoteid
//		self.tlsdata.flags = flags
//		self.tlsdata.local = local_flags
//		self.tlsdata.ipproto = ipproto
//		self.tlsdata.streamid = streamid
//		self.tlsdata.timeout = timeout
//
//	def close (self):
//		assert (self.plainsk is not None)
//		assert (self.plainfd >= 0)
//		self.plainsk.close ()
//		self.plainsk = None
//		self.plainfd = -1
//
//	def tlsdata_get (self, tlsvar):
//		return self.tlsdata [tlsvar]
//
//	def tlsdata_set (self, tlsvar, value):
//		self.tlsdata [tlsvar] = value
//
//	def starttls (self):
//		"""Initiate a TLS connection with the current settings, as
//		   provided during instantiation or through getter/setter
//		   access afterwards.  The variables that are required at
//		   this point are service and, already obliged when making
//		   a new instance, cryptfd.
//		"""
//		assert (self.cryptsk is not None)
//		assert (self.cryptfd >= 0)
//		assert (self.tlsdata.service != '')
//		try:
//			af = self.cryptsk.family
//		except:
//			af = socket.AF_INET
//		try:
//			if   self.cryptsk.proto in [socket.IPPROTO_UDP]:
//				socktp = socket.SOCK_DGRAM
//			elif self.cryptsk.proto in [socket.IPPROTO_SCTP]:
//				socktp = socket.SOCK_SEQPACKET
//			else:
//				socktp = socket.SOCK_STREAM
//		except:
//			socktp = socket.SOCK_STREAM
//		plainsockptr = socket_data ()
//		plainsockptr.unix_socket = self.plainfd
//		# Provide None for the callback function, SWIG won't support it
//		# We might at some point desire a library of C routine options?
//		rv = _starttls (self.cryptfd, self.tlsdata, plainsockptr, None)
//		self.plainfd = -1
//		self.cryptfd = -1
//		self.cryptsk = None
//		if rv < 0:
//			_tlspool.raise_errno ()
//		if self.plainsk is None:
//			self.plainfd = plainsockptr.unix_socket
//			self.plainsk = socket.fromfd (self.plainfd, af, socktp)
//		return self.plainsk
//
//	def prng (self, length, label, ctxvalue=None):
//		"""Produce length bytes of randomness from the master key, after
//		   mixing it with the label and optional context value in ctxvalue.
//		   The procedure has been described in RFC 5705.
//		   #TODO# Find a way to return the random bytes, and use the length
//		"""
//		buf = prng_data ()
//		rv = _prng (label, ctxvalue, length, buf, self.tlsdata.ctlkey)
//		if rv < 0:
//			_tlspool.raise_errno ()
//		else:
//			return buf
//
//	def control_detach (self):
//		"""Detach control of this connection.  Although the connection
//		   itself will still be available, control over it is diminished
//		   and its continuation is no longer dependent on the current
//		   connection.  You may need to pass tlsdata.ctlkey to another
//		   process, or use control_reattach(), before this is reversed
//		   in this process or another.
//		"""
//		_control_detach (self.tlsdata.ctlkey)
//
//	def control_reattach (self, ctlkey=None):
//		"""Reattach control of this connection.  The connection may have
//		   called control_detach() in this process or another.  To help
//		   with the latter case, its tlsdata.ctlkey must have been moved
//		   into this instance.
//		"""
//		_control_reattach (self.tlsdata.ctlkey)
//
//%}

%include "defines.h"
