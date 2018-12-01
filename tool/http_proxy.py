#!/usr/bin/env python
#
# tlspool proxy
#
#
# Since some.server can have a plain server certificate, this is
# more straightforward than using an HTTP or HTTPS proxy, for which
# we would need on-the-fly re-signing with a CA that the browser
# must accept.
#
# From: Rick van Rein <rick@openfortress.nl>
#  and: Henri Manson <info@mansoft.nl>

import re
import httplib
import socket
import tlspool
from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler

path_re = re.compile ('^http:\/\/([^:/]*)(?::([\d]+))?(/.*)?$')

class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

class RequestHandler(BaseHTTPRequestHandler):

    def __init__ (self, request, client_address, server):
        self.conn = None
        BaseHTTPRequestHandler.__init__ (self, request, client_address, server)

    def via_tlspool(self, host, port, path, post_body=None):
        print 'DEBUG: host to connect to is: %s' % host
        if self.conn is None:
            print 'DEBUG: creating new socket'
            # sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM)
            sox = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
            sox.connect ( (host, int (port or 443)) )
            cnx = tlspool.Connection (cryptsocket=sox)
            cnx.tlsdata.flags = ( tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT |
                                  tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER )
            cnx.tlsdata.remoteid = host
            cnx.tlsdata.ipproto = socket.IPPROTO_TCP
            cnx.tlsdata.service = 'http'
            try:
                sox = cnx.starttls ()
                self.conn = httplib.HTTPConnection(host,port=port)
                self.conn.set_debuglevel(1)
                self.conn.sock = sox
            except:
                self.send_response (403, 'Forbidden')
                return
        self.conn.putrequest(self.command, path, True, True)
        for hdnm in self.headers:
            self.conn.putheader (hdnm, self.headers [hdnm])
        content_length = self.headers.getheader('Content-Length')
        post_body = None
        if not content_length is None:
            post_body = self.rfile.read(int(content_length))
        self.conn.endheaders (message_body=post_body)
        response = self.conn.getresponse ()
        self.send_response (response.status, response.reason)
        for header in response.getheaders():
            (headername, headervalue) = header
            self.send_header (headername, headervalue)
        self.end_headers ()
        data = response.read ()
        print 'DEBUG: data is %d bytes long' % len (data)
        self.wfile.write (data)
        print 'DEBUG: exiting via_tlspool'

    def do_GET(self):
        print 'DEBUG: Request path is %s in' % (str (self.path),)
        uri = path_re.match (self.path)
        if uri is None:
            self.send_response (400, 'Bad Request')
            return
        print 'DEBUG: groups: %r' % (uri.groups (),)
        (host,port,path) = uri.groups ()
        port = int(port or '80')
        path = path or '/'
        if port % 1000 == 443:
            self.via_tlspool(host, port, path)
        else:
            self.copyfile(urllib.urlopen(self.path), self.wfile)

    def do_POST(self):
        self.do_GET()

ThreadingServer(('', 8080), RequestHandler).serve_forever()
