#!/bin/sh

ROOTDIR=`dirname "$0"`

mkdir -p m4
autoreconf --install
