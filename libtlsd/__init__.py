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

