/* This is the specifics module for SWIG mapping to Python.
 * It includes generic definitions from ../gen-tlspool.i
 *
 * This separation enables us to override function names, for instance
 * to raw/internal names, and then to add language-specific wrappers.
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

%module tlspool


/* Renames, prefixing "raw_" when wrapped below for better parameter handling
 */
%rename(pid) tlspool_pid;
%rename(open_poolhandle) tlspool_open_poolhandle;
%rename(ping) tlspool_ping;
%rename(raw_starttls) tlspool_starttls;
%rename(control_detach) tlspool_control_detach;
%rename(control_reattach) tlspool_control_reattach;
%rename(prng) raw_tlspool_prng;


// type maps

//TODO// This typemap crashes ping (...)
%typemap(in) pingpool_t *pingdata {
	// Code largely copied and adapted from ping_data_facilities_get
	ping_data *arg1 = (ping_data *) 0 ;
	void *argp1 = 0 ;
	int res1 = 0 ;
	PyObject * obj0 = 0 ;
	if (!PyArg_ParseTuple(args,(char *)"O:ping_data_facilities_get",&obj0)) SWIG_fail;
	res1 = SWIG_ConvertPtr(obj0, &argp1,SWIGTYPE_p_ping_data, 0 |  0 );
	if (!SWIG_IsOK(res1)) {
		SWIG_exception_fail(SWIG_ArgError(res1), "in method '" "ping_data_facilities_get" "', argument " "1"" of type '" "ping_data *""'"); 
	}
	arg1 = (ping_data *)(argp1);
	$1 = alloca (sizeof (pingpool_t));
	memcpy ($1->YYYYMMDD_producer,
			(arg1)->YYYYMMDD_producer,
			sizeof ($1->YYYYMMDD_producer));
	$1->facilities = (int) ((arg1)->facilities);
}


// apply the settings above as modifiers to the generic TLS Pool wrapping

%include "../swig-tlspool.i"



// full-blown Python code to include


//ONCE// %pythoncode %{
//ONCE// 
//ONCE// class TLSPoolConnection:
//ONCE// 	"""The TLSPoolConnection class wraps around a connection protected
//ONCE// 	   by the TLS Pool.  Create it with a socket that should hold the
//ONCE// 	   encrypted side of the flow (for instance, after negotiating a
//ONCE// 	   STARTTLS protocol over it in plain view) and optionally supply
//ONCE// 	   a socket to serve as the new plain text socket.  Also supply
//ONCE// 	   a dictionary with the various starttls_t fields, such as localid
//ONCE// 	   and flags.  A similar dictionary will be available after the
//ONCE// 	   successful setup of a TLS connection.  When TLS connection setup
//ONCE// 	   fails, an OSError exception is thrown, with informative errno
//ONCE// 	   and strerror settings, the latter with a descriptive string
//ONCE// 	   from the TLS Pool itself.
//ONCE// 	"""
//ONCE// 	def __init__ (self, cryptsock, tlsdata, plainsock=None):
//ONCE// 		...
//ONCE// 		self.cryptfd = cryptsock.fileno ()
//ONCE// 		if plainsock:
//ONCE// 			self.plainfd = plainsock.fileno ()
//ONCE// 		else:
//ONCE// 			self.plainfd = -1
//ONCE// 		starttlsdata = starttls_t ()
//ONCE// 		starttlsdata.service = ...;
//ONCE// 		rv = tlspool.raw_tlspool_starttls (
//ONCE// 					self.cryptfd,
//ONCE// 					starttlsdata,
//ONCE// 					self.plainfd,
//ONCE// 					None)
//ONCE// 		if rv < 0:
//ONCE// 			raise OSError (errno, errstr)
//ONCE// 		self.plainfd = rv
//ONCE// 		self.tlsdata = tlsdata
//ONCE// 
//ONCE// 	def __init__ (self, ctlkey):
//ONCE// 		
//ONCE// 
//ONCE// 	def __getattr__ (self, label):
//ONCE// 		return self.tlsdata [label]
//ONCE// 
//ONCE// 	def detach (self):
//ONCE// 		TODO
//ONCE// 
//ONCE// 	def reattach (self):
//ONCE// 		TODO
//ONCE// 
//ONCE// %}
