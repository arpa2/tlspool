Setup: System preparation
-------------------------

You are likely to want to copy the configuration file to a sensible place, such
as

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/etc/tlspool.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You would instead choose a location under your user account for a personal
installation. Note that a separate configuration file exists for use on Windows.
We will be editing bits and pieces of the configuration file below, but you may
already look around the file to get an impression of what it can do for you; the
file is exhaustively documented to help you understand the various settings.

When you run the TLS Pool as a system-wide solution, such as on a server, you
are probably going to let it run under its own userid and group:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
useradd tlspool
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Again, if you are trying to make the TLS Pool run under a personal account, you
would typically skip this step; instead, you would edit the configuration file
and set the `daemon_user` and `daemon_group` as well as `socket_user` and
`socket_group` to make the TLS Pool run as you.

 
