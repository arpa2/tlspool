Configuration Variable retrieval Tool
=====================================

>   *The configuration variables of the TLS Pool are often useful to other
>   applications.  There is some tooling to get it out.*

As part of `libtlspool`, there is a function `tlspool_configvar(3)` that returns
the textual value found, or NULL.  You can process that in any way you like.
The function can be provided with the configuration file, or it can guess where
to find it.

>   `Usage: tlspool-configvar [-c tlspool.conf] configvar...`

To facilitate scripts, a simple wrapper named `tlspool-configvar` can be called
to retrieve the value of one or more configuration variables.  Each found will
be printed on a line of its own in the same order as on the command line, and it
would be just the value, not the variable name or the separation equation
symbol.  When nothing is found, the program exits with value 1.

For scripts, this means that the following construct can be used:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
P11PATH=$(tlspool-configvar pkcs11_path 2>/dev/null || echo /path/to/p11.so)
echo $P11PATH
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Other variations are also possible, like using variable substitution:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
P11PATH=`tlspool-configvar pkcs11_path 2>/dev/null`
echo ${P11PATH:-/path/to/p11.so}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You are not likely to use the form that retrieves multiple variables at once,
but it is hardly more efficient anyway.

 
