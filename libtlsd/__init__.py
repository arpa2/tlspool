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

import socket
import passfd

def pass_to_daemon(conn, cmd='start-tls'):
    #print "Sending fd"
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect("/tmp/tlsd.sock")

    ret = passfd.sendfd(s, conn.fileno(), cmd)
    #print "Send %s bytes" % ret
    #print "Receiving fd..."
    fd, msg = passfd.recvfd(s)

    #print "  fd: %s" % fd
    #print "  message: %s" % msg

    if(msg.split()[0] == 'ERR'):
        conn.close()
        s.close()
        return conn, s, msg.split()[1], msg.split()[2]
    if(msg.split()[0] == 'OK'):
        sock = socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM)
        return sock, s, 0, msg.split()[1]

