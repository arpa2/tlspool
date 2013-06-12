#!/usr/bin/env python

import os
import socket
import sys
from threading import Thread

import argparse
import logging
from libtlsd.session import SessionHandler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description='RP2 TLS daemon')
    parser.add_argument('-s', dest='socket', default='/tmp/tlsd.sock', help='the socket file to use')
    parser.add_argument('-d', '--daemonize', action='store_true', help='run the program as a daemon')
    parser.add_argument('-v', '--verbose', dest='verbose', action='store_true', help='show debug output')
    args = parser.parse_args()

    if(args.verbose):
        logger.setLevel(logging.DEBUG)
        logging.getLogger('libtlsd').setLevel(logging.DEBUG)

    logger.debug("Creating socket")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        logger.debug("Remove old socket file: %s" % args.socket)
        os.remove(args.socket)
    except OSError:
        pass

    try:
        logger.debug("Binding to socket: %s" % args.socket)
        s.bind(args.socket)

        logger.info("Waiting for connection")
        s.listen(1)
    except socket.error as msg:
        logger.error(msg)
        s.close()
        return 1

    while True:
        conn, addr = s.accept()
        handler = SessionHandler(conn, addr)
        handler.start()



if __name__ == "__main__":
    sys.exit(main())