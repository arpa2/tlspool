#!/usr/bin/env python

#   Copyright (C) 2013 René Klomp (rene.klomp@os3.nl)
#   Copyright (C) 2013 Thijs Rozekrans (thijs.rozekrans@os3.nl)
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import socket
import sys
from threading import Thread

import argparse
import logging
from libtlsd.session import SessionHandler
from daemon import Daemon

logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(thread)d:%(name)s: %(message)s')
logger = logging.getLogger(__name__)

class TLSDaemon(Daemon):
    def set_args(self, args):
        self.args=args

    def run(self):
        logger.debug("Creating socket")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            logger.debug("Remove old socket file: %s" % self.args.socket)
            os.remove(self.args.socket)
        except OSError:
            pass

        try:
            logger.info("Binding to socket: %s" % self.args.socket)
            s.bind(self.args.socket)

            logger.info("Waiting for connection")
            s.listen(1)
        except socket.error as msg:
            logger.error(msg)
            s.close()
            return 1

        sess_id = 1
        while True:
            conn, addr = s.accept()
            logger.info("Incoming connection. Starting SessionHandler thread with id: %d",sess_id)
            handler = SessionHandler(conn, addr, sess_id)
            handler.start()
            sess_id+=1

def main():
    parser = argparse.ArgumentParser(description='RP2 TLS daemon')
    parser.add_argument('-s', dest='socket', default='/tmp/tlsd.sock', help='the socket file to use')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='show debug output')
    parser.add_argument('-l', '--logfile', dest='logfile', help='write log to a file')
    parser.add_argument('command', choices=['start', 'stop', 'restart', 'foreground'])
    args = parser.parse_args()

    if(args.logfile != None):
        hdlr = logging.FileHandler(args.logfile)
        formatter = logging.Formatter('%(asctime)s %(thread)d %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logging.getLogger('libtlsd').addHandler(hdlr)
        
    if(args.verbose):
        logger.setLevel(logging.DEBUG)
        logging.getLogger('libtlsd').setLevel(logging.DEBUG)

    daemon = TLSDaemon('/tmp/tlsd.pid')
    daemon.set_args(args)
    if args.command == 'foreground':
        daemon.run()
    elif args.command == 'start':
        daemon.start()
    elif args.command == 'stop':
        daemon.stop()
    elif args.command == 'restart':
        daemon.restart()
    else:
        print "Unknown command"
        sys.exit(2)

if __name__ == "__main__":
    sys.exit(main())