#!/bin/bash
#
# Build distribution with CMake and test with CTest
#
# From: Rick van Rein <rick@openfortress.nl>



info() {
	echo
	# Red=31, Bright=1
	echo '[31;1m'"$@"'[0m'
}

cmd_ok() {
	# Green=32, Bright=1
	echo '[32;1mbash$ '"$@"'[0m'
	"$@"
}

maybe_exit() {
	EXITVAL=${1:-$?}
	if [ $EXITVAL -ne 0 ]
	then
		info Error exit value $EXITVAL
		exit $EXITVAL
	fi
}

cmd() {
	# Green=32, Bright=1			# Yellow=33
	echo '[32;1mbash$ '"$@"'[0m (dir is [33m'`pwd`'[0m)'
	"$@"
	maybe_exit
	# EXITVAL=$?
	# maybe_exit $EXITVAL
}

cmake_depend() {
	PKG="$1"
	DIR="/builds/arpa2/$PKG"
	cmd mkdir -p "$DIR"
	pushd "$DIR"
	info Building CMake project $PKG
	cmd mkdir build
	cmd cd build
	cmd cmake -D DEBUG:BOOL=OFF ..
	cmd make
	cmd make install
	popd
}

cmake_depend_git() {
	PKG="$1"
	REPO="${2:-https://github.com/arpa2/$PKG}"
	BRANCH="${3:-master}"
	DIR="/builds/arpa2/$PKG"
	info Fetching CMake project $PKG
	cmd git clone -b "${BRANCH}" "${REPO}" "${DIR}"
	cmake_depend "$PKG"
}

info Changing to distribution
cmd pwd
cmd cd /io

info Installing Dependencies
export DEBIAN_FRONTEND=noninteractive
cmd apt-get install -y libdb5.3-dev softhsm2 libgnutls28-dev gnutls-bin libldns-dev libunbound-dev libpython-dev swig ppp python2.7 python-setuptools
cmd $PYINST six
cmd $PYINST asn1ate

info Building Source-Code Dependencies
cmake_depend_git arpa2cm 
cmake_depend_git quick-der https://github.com/vanrein/quick-der

info Configuring...
cmd mkdir -p build
cmd cd build
cmd cmake -D DEBUG:BOOL=ON -D TEST_UNDER_TLSPOOL:BOOL=ON -DCMAKE_INSTALL_PREFIX=/ ..

info Building...
cmd make
cmd make install
cmd ldconfig

info Installing DNS root key...
cmd mkdir -p /etc/unbound
cmd cp ../etc/root.key /etc/unbound/root.key

info Creating tlspool user...
cmd_ok useradd tlspool

info Setting up SoftHSM2...
cmd chmod ugo+rx /etc/softhsm && chmod ugo+r /etc/softhsm/softhsm2.conf
cmd chmod go+rx /var/lib/softhsm && mkdir -p /var/lib/softhsm/tokens && chmod go+rwx /var/lib/softhsm/tokens
cmd su -c 'softhsm2-util --init-token --free --label TLS_Pool_dev_data --so-pin=sekreet --pin=1234' tlspool

info Setting up test data...
mkdir -p /var/db/tlspool
chown tlspool /var/db/tlspool
chown -R tlspool ../testdata && ( cd ../testdata ; su -c 'TOOLDIR=../build/tool make all' tlspool || su -c 'TOOLDIR=../build/tool make all' tlspool ) && su -c 'cp -pir ../testdata/* /var/db/tlspool' tlspool

info Starting System Logging...
cmd /etc/init.d/rsyslog start

info Starting the TLS Pool...
cmd tlspool-daemon -kc /etc/tlspool.conf

info Running Tests...
cmd_ok ctest > ctest.tty
TESTRESULT=$?

if [ $TESTRESULT -ne 0 ]
then
	cmd_ok ctest --rerun-failed
	LOGSIZE=FAILED
else
	LOGSIZE=ALL
fi

info CTest logfile for $LOGSIZE tests:
cat Testing/Temporary/LastTest.log

maybe_exit $TESTRESULT

info Successful return from $0
cmd exit 0

