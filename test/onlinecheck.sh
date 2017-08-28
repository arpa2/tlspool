#! /bin/sh
EXE="$1"

"$EXE" ../etc/tlspool.conf | tee | grep -v 'UNEXPECTED OUTPUT FAILURE'
