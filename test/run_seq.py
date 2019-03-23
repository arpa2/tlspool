#!/usr/bin/env python
#
# Run a program sequentially, that is, print "--\n" after it is done.
# This program can be useful together with Pypeline, to run "normal"
# commands.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import subprocess


retcode = subprocess.call (sys.argv [1:])

print ('--')

sys.exit (retcode)
