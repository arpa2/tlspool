IRCproxy — hoe ook alweer?
--------------------------

Demo voor de TLS Pool.  **NOT YET WORKING**

### IRC commando:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PRIVMSG john,mike STARTTLS,STARTGSS qp7x0z9x0
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verzonden naar remote; die reageert soortgelijk.

Vergelijk strings, eis ongelijk, en ken toe als client \< server.

### Daadwerkelijk verkeer:

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
PRIVMSG mike TLS lak2j3wc0aw439m+zs0d9g/drt===
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Elke regel is afzonderlijke base64-gecodeerd en wordt naar TLS gevoed. Meerdere
bestemmingen zou waanzin zijn voor TLS; de proxy bouwt afzonderlijke
verbindingen op naar elke TLS-peer, zelfs als `PRIVMSG` naar meerdere tegelijk
gezonden wordt.

De gedecodeerde stream is een reeks commando’s zoals `PRIVMSG` maar mogelijk ook
andere die IRC herkent.

### IRCHandler methods:

-   `IRCHandler` ontvangt commando's

-   `handle_upload()` verwerkt `PRIVMSG` door TLS af te dwingen

-   `handle_download()` verwerkt `PRIVMSG` door ook TLS af te dwingen

-   `have_tlsmap("nick")` levert een TLS-enabled plaintext fd af voor `PRIVMSG`
    in/out

-   `upload_cmd()` verzendt commando-triple letterlijk naar server

-   `download_cmd()` verzendt commando-triple letterlijk naar client

-   `have_tlsmap()` hergebruikt een bestaande TLS-verbinding als dat kan

-   `have_tlsmap()` maakt zonodig een TLS-verbinding aan als `PrivateChannel`
    object

### PrivateChannel attributes and methods:

-   The TLS Pool must use a socketpair as `cryptfd`; it is mapped to
    `PRIVMSG`/base64

-   The TLS Pool must use a socketpair as `plainfd`; traffic must be split and
    recombined

-   The `plainfd` from the TLS Pool is returned from the `plaintext_socket()`

-   The `ircprox` is used to access `ircprox.srv` directly

-   `intsox` is passed to the TLS Pool as the to-be-TLS handle

-   `extsox` exchanges TLS fragments for mapping to/from `PRIVMSG`/base64

-   `plainfd` is set to the IRC proxy’s client-side file handle

**TODO:**

-   DONE intsox/extsox are poor names

    -   DONE poolcrypt+chancrypt and poolplain+chanplain are better

-   DONE tlsmap should be renamed to peerprivchan

-   DONE uploaded commands can be actively redirected to a `PrivateChannel`
    method

    -   DONE `privchan.handle_upload_plain_cmd ( (pfix,cmd,args) )`

    -   must pass plain data through TLS Pool instead of relaying directly!

-   DONE downloaded commands can be actively redirected to a `PrivateChannel`
    method

    -   DONE `privchan.handle_download_crypt_cmd ( (pfix,cmd,args) )`

    -   DONE must pass TLS data through TLS Pool instead of relaying directly!

    -   DONE after unpacking base64, first split lines and require trailing CRLF
        on last

-   NOMORE probably need a queue for commands in both directions, when not ready
    yet

    -   ALT send but count insecurely sent commands, report at start of security

-   NOMORE probably need syncing on such commands

-   do we really need a Thread for STARTTLS? events trigger it fine

    -   but TLS Pool may initiate new fragments to be sent

    -   this can be done as in OpenVPN, pulling out all that it has to give

    -   should we set TLS timeout to infinity? especially nice with non-blocking
        use

-   DONE should not have to avoid GC when privchan in new map array

-   OPTION: Consider supporting unencrypted PRIVMSG as well

    -   Report explicitly when state is changed (can this ever be faked?!?)

    -   Manually issue a command /STARTTLS and then require TLS to be active

    -   Additionally support a command /SECRET to agree a 128-bit secret in hex

    -   FORNOW: self.insecure counts insecure messages; reported later on

### TODO on key-exchange-tlsmail.py

-   RENAME to mail-key-exchange.py

-   Add a comment about neither setting nor extracting `tlsdata.plainfd` — no
    TLS data
