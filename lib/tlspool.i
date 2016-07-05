# Declaration of libtlspool for swig
#
# We use swig to generate wrappers for Python.
#
# We also include the generated result in the Git repository for TLS Pool,
# so there is no requirement to install Swig unless you run "make veryclean"
# instead of the usual "make clean".
#
# From: Rick van Rein <rick@openfortress.nl>


%module tlspool

%{
#include <tlspool/commands.h>
#include <tlspool/starttls.h>
%}

%include <tlspool/commands.h>
%include <tlspool/starttls.h>

