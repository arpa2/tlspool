#!/usr/bin/env python
#
# Run a program in parallel, that is, print "--\n" before it starts.
# This program can be useful together with Pypeline, to run "normal"
# commands.
#
# From: Rick van Rein <rick@openfortress.nl>


import sys
import subprocess


print ('--')

retcode = subprocess.call (sys.argv [1:])

sys.exit (retcode)
