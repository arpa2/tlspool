Setup SteamWorks: PulleyBack
============================

>   *The commands provided with the TLS Pool allow you to manage its dynamic
>   configuration through databases.  This will suffice for your scripting
>   needs.  If you want a more advanced integration with configuration update
>   subscriptions, you may want to use the SteamWorks integration, and process
>   updates pulled from LDAP.*

Most administrative solutions rely on actively pushing changes to end points,
either manually or, after getting too bored, with scripted automation.
SteamWorks takes a somewhat different angle; it assumes that clients will
subscribe for updates, and pulls them in.  It uses LDAP for that, and
specifically its excellent SyncRepl capability which allows for
virtually-instant updates to any subscribed LDAP client, as well as picking up
where it left off by any clients that happen to be offline during an update.

Being a generic framework, SteamWorks has a powerful scripting language named
[PulleyScript](http://steamworks.arpa2.net/spec/pulley.html) that connects to an
LDAP source, pulls out information and offers any changes for local processing.
This local processing is done through backend plugins, and in the case of the
TLS Pool such a “PulleyBack” plugin is provided as part of the TLS Pool.

Depending on the configuration in the PulleyScript, the PulleyBack can deliver
information to the TLS Pool databases `localid.db`, `disclose.db` and `trust.db`
— which gives it great authority over the credentials and trust under which the
TLS Pool operates.  Of course, it all depends on the actual PulleyScript how
much of this authority is actually being used.

**TODO:** Provide example scripts for each of the databases and, within these,
the variations that might be of interest.  Emphasise the potential for
variations in the LDAP schemes pulled from.
