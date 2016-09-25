Working with libtlspool
=======================

>   *The TLS Pool library provides a number of functions to support programmers
>   who wish to add TLS to their programs.*

To use the TLS Pool, the following things are useful.  You may want to take a
look at programs such as
[testcli.c](https://github.com/arpa2/tlspool/blob/master/tool/testcli.c) and
[testsrv.c](https://github.com/arpa2/tlspool/blob/master/tool/testsrv.c) for
examples.

Client programs tend to include the following files:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#include <tlspool/commands.h>
#include <tlspool/starttls.h>
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

They tend to be linked with the TLS Pool library:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
gcc prog.c -ltlspool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The API functions are well documented in manual pages.  Please read the
following for normal operation:

-   `tlspool_socket(3)`

-   `tlspool_ping(3)`

-   `tlspool_starttls(3)`

Special functions may rely on the following added functions:

-   `tlspool_control_detach(3)`

-   `tlspool_control_reattach(3)`

Finally, software that interacts with users and/or is scripted may use the
following:

-   `tlspool_configvar(3)`

-   `tlspool_pin_service(3)`

-   `tlspool_localid_service(3)`

The static libraries form an archive; it is split into objects with these
separate uses in mind, and the possibility of linking in less code.  The dynamic
library is complete to facilitate sharing it between processes.
