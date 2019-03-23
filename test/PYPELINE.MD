# Pypeline to test Network Programs

> *The pypeline program is a handy tool for setting up programs
> that do things on a network, and construct reliable tests that
> roll out in the right order.  In addition, resources can be
> allocated and passed into the programs as command arguments.*

Pypeline creates networking pipelines, where one program provides
information for the ones that follow.  The pypeline starts the
program in a fixed order, and synchronises with the programs to
avoid race conditions.  The programs need to be built for the
interaction, though.


## Program Interaction: Initial, FreeRun, Results

Every program passes through three interactions with the pypeline:

  * **Initial** is the phase during which all output is copied but
    an end marker of the initial phase is awaited.  This is the
    string `--` on a line of its own, written to `stdout` and
    flushed out to cause immediate processing.  An error commences
    when the output ends before this marker has occurred.

  * **FreeRun** is the phase during which the program does its
    work and runs until completion.  At the end, the pypeline
    collects the `exit` state and requires that they have a
    desired exit value.  Any other situation is considered a
    failure.

  * **Results** is the collection of the exit value, reported as
    either `success` or `failure`.  When the marker `--` was not
    found before the program ended, the result is marked as an
    an error, even if a desired exit code was supplied during
    this early termination.  After the end marker, a desired exit
    value will be required for a correct overall test result.


## Starting Programs

The `pypeline` command line mentions multiple programs separated
by `--` markers.  These programs are started one by one, in the
order from the last on the command line to the first.  When the
first initiates any network traffic, this would work.

To synchronise program start, the end marker of the initial phase
is awaited before another program is started.  This means that
only one initial phase runs at a time, and in a predictable order.
This is meant to allow resource setup, such as the creation of a
listening network socket before another program sends to it.

It is the free running phase during which programs can run in
parallel with others.  Some may still be initialised, of course;
the programs do not wait after sending the `--` marker that
indicates its switch from initial to free running phase.

By default, a program is expected to produce exit value 0 on
success, or anything else when an error occurs.  But to support
explicitly desired failures, it is possible to provide one or
more exit values before the command.  This would take the form
of the desired numeric values separated by a comma; if just
one numeric value is desired, this is just that value.  Note
that this means that command names cannot look like a number
or a list of numbers; we have no escape for that.


## Stopping Programs

The collection of results occurs when a program ends.  This may
be its own initiative, or in response to a termination signal
sent by the `pypeline` program.  Once all programs have ended,
the overall test result is produced.

Programs that do not use a signal will continue until they end
themselves.  It is usually a good idea to build in a timeout,
for instance set to 10 seconds.  The program can then decide
whether the timeout is an error.  Programs with a signal would
run until completion, or perhaps also until a timeout, but the
presence of a signal allows `pypeline` to terminate them at any
convenient time; this is useful for programs that otherwise run
forever, because they have no clue about the amount of work
that has been done, such as a daemon.

The end game of `pyperline` proceeds in three phases.  During
phase 1, it waits until all programs without a signal have
ended.  During phase 2, any programs with a signal that are
still running will be sent all the signals that were given.
During phase 3, it waits until all programs with a signal
have also ended.  At that point, the overall exit value for
the test is determined and returned as the overall result.


## Pyperline can provide Resources

A number of command line arguments is special.  The are used to
name resources to be allocated, supplied as a textual value
on the command lines of the various programs.  The same textual
value may be setup in multiple places, when they use the same
resource name.

The resource names that are replaced with textual values are:

  * `TCP:<key>`, `UDP:<key>` and `SCTP:<key>` represent network
    sockets of the local host name, where the `<key>` serves
    to identify them within the protocol.  The port is
    allocated by `pypeline` by binding an emphemeral socket
    and closing it immediately.  These resource names are
    replaced with the port number in ASCII notation.

  * `IP:` with optional ignored extra characters represents the
    IP address of the host.  This may be an IPv6 or IPv4
    address.  The IP replaces this resource name.

  * `SIG:<name>` indicates a signal to be sent.  The signal
    should be known to the Python module `signal` as the
    name `SIG<name>`, such as `SIG:HUP` to indicate `SIGHUP`.
    The corresponding numeric value will replace this
    resource name.

  * `FILE:<key>` marks a temporary file where the `<key>`
    serves to identify that file.  The actual file contents
    can be constructed by any program, but only the name
    is created by `pypeline`, no contents, and this name
    is used to replace this resource name.  The file will
    removed when `pypeline` exits.

  * `RNDHEX:<key>` inserts at least 128 bits of random data,
     where `<key>` serves to identify the data.  The form
     `RNDHEX` indicates representation in hexadecimal form.
     We might add other forms, sharing the `<key>` to access
     the underlying binary data.  The intent is of course to
     raise the fact that arbitrary data can be passed above
     the level of any suspicion of being accidentally the
     same; if 128 bits can convince cryptographers, then it
     should do the same for testers.


## Example uses in CMakeLists.txt

This is an example use in a `CMakeLists.txt` file:

    add_test (NAME t_tcpwrap COMMAND python pypeline
	    python tcpclient IP:FRONT UDP:FRONT bin/krb5-as-req.der bin/krb5-as-rep.der
	    --
	    ./tcpwrap_test IP:FRONT UDP:FRONT IP:KDC UDP:KDC SIG:HUP
	    --
	    python fakekdc IP:KDC UDP:KDC bin/krb5-as-req.der bin/krb5-as-rep.der
	    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

This creates three programs, that prefixes `tcpclient`,
`tcpwrap_test` and `fakekdc` to output lines.

The IP address of the host is used in a number of places;
the various names `IP:FRONT` and `IP:KDC` all produce the
same host name.  Two different UDP ports are allocated,
and their numbers substituted for `UDP:FRONT` and
`UDP:KDC`, respectively.  Finally `SIG:HUP` is replaced
with the signal number for `SIGHUP`.

An example that would function in the same way could be

    add_test (NAME t_tcpwrap COMMAND python pypeline
	    python tcpclient localhost 54837 bin/krb5-as-req.der bin/krb5-as-rep.der
	    --
	    ./tcpwrap_test localhost 54837 localhost 61382 1
	    --
	    python fakekdc localhost 61382 bin/krb5-as-req.der bin/krb5-as-rep.der
	    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

The first program started is `fakedkdc`, until its output
holds a line `--`.  Then `tcpwrap_test` is started, until
its output holds a line `--`.  Finally, `tcpclient` is
started and its output is monitored for a line `--`.
The wait for the `--` markers allows the programs to
initiate listening sockets, suitable for initial traffic
from `tcpclient` to `tcpwrap_test` to `fakekdc` and, once
established, traffic can flow back.

The programs communicate freely until `tcpclient` and
`fakekdc` finish.  At that point, the `SIGHUP` signal
is sent to `tcpwrap_test` and its finish is awaited.
There are no temporary files because there are no
`FILE:<key>` resources, but these would be removed
after all the programs have finished.

Now the complete return value is constructed; any error
exits with value 1 but all ok exits.

