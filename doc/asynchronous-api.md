# Asynchronous TLS Pool interaction

> *The TLS Pool library intends to provide a simple API
> to the code.  Asynchronous or event-driven programs
> are not well served with this simplicity.  So we shall
> pull the API to bits and pieces.*

A few things change for users of the asynchronous or
event-driven API; for those who want to use the normal,
blocking calls there is no change.  These blocking
calls will internally be torn apart and distributed
somewhat differently, but the effect will be the same.

**TODO:** We should find a way to allow minimal linking.
This involves proper registration of the library variants
in both `pkg-config` and `CMake`.  Until we have found
out how to do that, we shall provide both libraries to
all, linking first the synchronous wrappers and then
the asynchronous ones.


## Processing Callbacks

The operations on the TLS Pool all involve sending a message
and awaiting the response, so essentially they are already
asynchronous.  In some cases, a few iterations may be needed,
such as to test if a requested server name is acceptable.
These already take the form of callbacks.   Callbacks will
generally be used to talk back to the application.

We need a general callback approach:

  * Register a callback and data when sending to the TLS Pool

  * Invoke the callback with data on reply from the TLS Pool

  * Have an option to cancel a request for callback (without undo)

  * Let the callback data be a TLS Pool command and an opaque pointer

  * The sent-back response needs interpretation; provide library support

The aim should be to split the current synchronous library
functions into these partial functions, and replace the
current code base with such asynchronous calls, plus the
master thread.  We should make the asynchronous library a
separate one, so it can be linked without loading threading
into an asynchronous program.  (But is this thread-caused
split necessary under any platform's library formats?)


## Taking Responsibility

The synchronous API runs a *master thread* that listens to the
TLS Pool socket, and reports any output to the waiting
client threads.  When a connection to the TLS Pool is
asynchronous, it will not start such a thread.

The task of the master thread must therefore be assumed
by the asynchronous user.  Basically, the master thread
does this:

```
Forever do {
   Connect to the TLS Pool;
   While connected {
      Wait for messages from the TLS Pool;
      Find the party being responded to;
      Trigger that party over a lock.
   }
   Terminate any pending requests.
}
```

While this is running, clients will send a message to
the TLS Pool and block until they are unlocked by the
the master thread.

An asynchronous process implements the work of the
master thread, probably scattered over a few pieces
of code.


## Functions in the Asynchronous API

An asynchronous process consists of ingredients to this
yourself:

  * `tlspool_async_open()` returns a fresh socket
    connected to the TLS Pool.  You should call it once
    and register it with a callback in your event loop.

    When a message can be read, it should be processed.

    When an error occurs, pending requests should all
    be cancelled.  You would usually continue to open a
    new socket, with exponential fallback in case of
    failure.  Or you may want to exit your program.

  * `tlspool_async_request()` sends a request to the
    TLS Pool along with a callback routine.

    Requests for a given socket get together in one data
    structure until the response arrives.  The memory
    for the data structure is allocated by the caller.

  * `tlspool_async_cancel()` drops a request from the
    data structure holding the callbacks.  The memory
    for this structure can now be freed.  Measures
    must be taken to avoid reuse of the identity of
    the request, at least before the TLS Pool has
    answered to it.

  * `tlspool_async_process()` reads any messages from a
    given TLS Pool socket, and triggers whatever callbacks
    are available.  It is no error if there are no
    messages waiting to be handled.

  * `tlspool_async_closed()` sends a rejection to any
    pending requests for a given TLS Pool socket.  This
    should be called when the TLS Pool socket closes
    down on either side.

It is currently undecided if these functions are safe for
re-entry; event-driven styles tend to be single-threaded,
at least within a process.


## Data Structures

We need a data structure for the callbacks:

```
struct tlspool_async_request {
	UT_hash_handle hh;
	void (*cbfunc) (struct tlspool_request *cbdata);
	struct tlspool_command cmd;
};
```

The `hh` field makes the structure hashable with
[uthash](http://troydhanson.github.io/uthash/userguide.html)
and we will use the `cmd.pio_reqid` field as its key.

The `cbfunc` is simply called with the structure that
contains it.  By the time this is done, it has been
taken out of the hash table.  The `cmd` has been
filled with the information from the TLS Pool (or it
has been locally provided with error information)
and should provide all desired information.

The connectivity around a TLS Pool socket uses the
following data structure:

```
struct tlspool_async_pool {
	tlspool_handle_t handle;
	size_t cmdsize;
	struct tlspool_async_request *requests;
	char YYYYMMDD_producer [8+128];
	uint32_t facilities;
};
```

The `cmdsize` is set to `sizeof (struct tlspool_command)`
and can be used to ensure that software modules are all
on the same (memory) page.

The fields `YYYYMMDD_producer` and `facilities` are
taken from a `PIOC_PING_Vx` command or, when this
has not been called yet, it is filled with only
zeroes.

These simple structures suffice for the
asynchronous API.  The rest is already defined in
the command structure in `<tlspool/commands.h>`.


## Include File and Library

The asynchronous functions and data structures can
be found in include file `<tlspool/async.h>`, which
includes `<tlspool/commands.h>`.

The name of the shared library (on POSIX systems)
is `libtlspool_async.so`, with the usual variants
for versioning and aberrant operating systems.


## Future Options

There are two possible continuations after this,
and they may combine very interestingly.

**Remote TLS Pool** would be a drop-in replacement
that wrap the `tlspool_command` structure into a
network-portable variation.  It is more likely to
replace the asynchronous API than the synchronous.

**Embedded systems** want TLS, but cannot always
afford it in terms of resources such as memory and
CPU.  The asynchronous API should be most useful
to these systems, because of its simplicity.


## Further Reading

This work is based on
[this issue](https://github.com/arpa2/tlspool/issues/57)
in the GitHub issue tracker.

