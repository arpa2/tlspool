Setting up the TLS Pool Dæmon
=============================

>   *After all the preparation has been done, it is relatively simple to start
>   the TLS Pool itself.*

Have a last look through your configuration file, which is usually in
`/etc/tlspool.conf` if you installed it system-wide.  Take note of at least the
following settings:

-   `socket_name` defines the path of the UNIX domain socket to the TLS Pool

-   `socket_user` and `socket_group` define the user and group that may access
    its socket, together with `socket_mode` for its access mode

-   `daemon_user` and `daemon_group` define the user and group running the TLS
    Pool

-   `db_envdir` should now be set to the absolute path at which you setup your
    BerkeleyDB database environment

-   `pkcs11_path` should point to your PKCS \#11 shared library

-   `pkcs11_token` should hold the identifying information of your token,
    created as per the directions provided by its manufacturer.  You usually
    mention things like `model`, `manufacturer` and `token` in this token-query
    description; you may want to add the `serial` if you need an attribute that
    usually identifies a token uniquely given the other settings

-   `pkcs11_pin` should be present, and only be present, if you intend to avoid
    any questions to user land about the PKCS \#11 PIN to use

-   `tls_dhparamfile` is for caching only, and will at worst cause a warning;
    you should however have it appointed to an absolute path for best results,
    like `/var/db/tlspool/db-params.pkcs3`

-   `tls_onthefly_signcert` and `tls_onthefly_signkey` should only be set if you
    intend to support on-the-fly creation of certificates.  If they exist, they
    should represent existing credentials, and any file reference should be an
    absolute path

-   `dnssec_rootkey` should be in an absolute path, such as
    `/var/tlspool/db/root.key`; be sure to download to that location a
    *validated* version of the root key distributed with the TLS Pool or
    obtained through

    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    dig . dnskey | grep 257
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once you are happy with your configuration, launch the TLS Pool with

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
tlspool -kc /etc/tlspool.conf
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The argument `-c` provides a configuration file, and `-k` is used to kill any
TLS Pool running prior to this call.  You can repeat this command if ever you
change the configuration file and need the TLS Pool to restart to read the new
configuration.

Once the TLS Pool is running, it will output information as per the settings in
`log_level`, `log_filter` and `log_stderr`.  By default, that is quite a lot.
