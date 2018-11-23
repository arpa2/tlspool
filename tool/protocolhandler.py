#!/usr/bin/env python
#
# protocolHandler for "web+tlspool" URI scheme.
#
# This can be registered with some browsers, as described on
# https://developer.mozilla.org/en-US/docs/Web/API/Navigator/registerProtocolHandler
#
# The intention is to redirect URIs of our own design, like
#    web+tlspool://orvelte.nep/bakkerij
# into
#    https://some.server/?uri=web+tlspool://orvelte.nep/bakkerij
# with some escapes in the URI, of course.
#
# Since some.server can have a plain server certificate, this is
# more straightforward than using an HTTP or HTTPS proxy, for which
# we would need on-the-fly re-signing with a CA that the browser
# must accept.
#
# From: Rick van Rein <rick@openfortress.nl>


import os
import sys
import re
import time

import socket
import urllib
import urlparse

import tlspool

from SocketServer import ThreadingMixIn
from BaseHTTPServer import HTTPServer
from SimpleHTTPServer import SimpleHTTPRequestHandler


path_re = re.compile ('^.*[?&]uri=(.*)$')


class ThreadingServer(ThreadingMixIn, HTTPServer):
    pass

class RequestHandler(SimpleHTTPRequestHandler):

    def do_GET(self):
        #TODO# Can we really just process GET requests?
        print 'DEBUG: Request path is %s' % (str (self.path),)
        uri = path_re.match (self.path)
        if uri is None:
            self.send_response (400, 'Bad Request')
            return
        (uri,) = uri.groups ()
        uri = urllib.unquote_plus (uri)
        uri = urlparse.urlparse (uri)
        print 'DEBUG: URI to connect to is', uri
        # sox = socket.socket (socket.AF_INET6, socket.SOCK_STREAM)
        sox = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
        sox.connect ( (uri.hostname, int (uri.port or '443')) )
        cnx = tlspool.Connection (cryptsocket=sox)
        cnx.tlsdata.flags = ( tlspool.PIOF_STARTTLS_LOCALROLE_CLIENT |
                              tlspool.PIOF_STARTTLS_REMOTEROLE_SERVER |
                              tlspool.PIOF_STARTTLS_FORK |
                              tlspool.PIOF_STARTTLS_DETACH )
        cnx.tlsdata.remoteid = uri.hostname
        cnx.tlsdata.ipproto = socket.IPPROTO_TCP
        cnx.tlsdata.service = 'http'
        try:
                sox = cnx.starttls ()
        except:
                self.send_response (403, 'Forbidden')
                return
        print 'DEBUG: Sending headers:\n%s', str (self.headers)
        sox.send (str (self.headers) + '\r\n')
        #TODO# Probably too simple
        self.end_headers ()
        self.send_response (200, 'OK')
        self.wfile.write (sox.read ())

ThreadingServer(('', 8080), RequestHandler).serve_forever()

