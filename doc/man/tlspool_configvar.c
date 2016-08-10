.TH TLSPOOL_CONFIGVAR 3 "August 2016" "ARPA2.net" "Library Calls"
.SH NAME
tlspool_configvar \- Retrieve a TLS Pool configuration variable value
.SH SYNOPSIS
.B #include <tlspool/starttls.h>
.sp
.B char *tlspool_configvar (char *\fIcfgfile\fB, char *\fIvarname\fB);
.SH DESCRIPTION
.PP
.BR tlspool_configvar ()
fetches the value of a configuration file variable as setup for the
TLS Pool.  The configuration file can be provided in the 
.IR cfgfile parameter
or, if it is NULL, then first the environment variable
.BR TLSPOOL_CFGFILE
and, failing to find that, it tries the compile-time setting
.BR TLSPOOL_DEFAULT_CONFIG_PATH .

.SH "RETURN VALUE"
The value returned is NULL when the requested variable was not
found, but also when the configuration file did not load.  The
error output may hold further hints on the cause of problems.
.SH AUTHOR
.PP
Written by Rick van Rein of OpenFortress.nl, for the ARPA2.net project.
.SH "REPORTING BUGS"
.PP
For any discussion, including about bugs, please use the mailing list
found on
.IR http://lists.arpa2.org/mailman/listinfo/tls-pool .
.PP
Please read the software distribution's
.IR README ", " INSTALL " and " TODO " files"
for information about the
.I tlspool
implementation status.
.SH COPYRIGHT
.PP
Copyright \(co 2016 Rick van Rein, ARPA2.net.
.PP
ARPA2 is funded from InternetWide.org, which in turns receives donations
from various funding sources with an interest in a private and secure
Internet that gives users control over their online presence.  This particular
project has been sponsored in part by NCSC.
.SH "SEE ALSO"
.IR tlspool "(8)"
.PP
The TLS Pool API is documented in the include file
.IR <tlspool/commands.h> " and " <tlspool/starttls.h>
for C, and the
.I tlspool.py
module for Python.
.PP
Online resources may be found on the project home page,
.IR http://tlspool.arpa2.net .
