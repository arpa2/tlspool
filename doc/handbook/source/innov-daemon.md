Separation from Applications
============================

>   *A major choice in the design of the TLS Pool is to make it a background
>   program, or a dæmon.  This separates it completely from applications, with
>   protection of the operating system which is usually specialised in keeping
>   processes separated and secure from each other’s influence.*

Modern operating systems all employ a Memory Management Unit, a hardware layer
that implements virtual memory for each process.  These virtual memories are
kept separate and any attempt to get to another process’s memory is either not
linked or leads to a disruption of the offending program’s run.  On POSIX
machines for example, a “segmentation fault” causes the immediate breakdown of
the program, without even touching any other program.

Now imagine a browser.  It hosts a lot of technology, ranging from front-end
friendly scripts written in JavaScript, but it also connects to remote sites and
may employ credentials to get there.  Classically, these have been operating at
different layers of the protocol stack, but new movements are even trying to
integrate cryptographic operations in the same JavaScript that runs code as
adverse as advertisements.  In short, browsers are a melting pot of attitudes to
our privacy, and only when it has been programmed to perfection is it completely
reliable in handling it.

This challenged-by-default setup of a browser can be greatly improved if it
offloads the handling of TLS and all its secrets and credentials.  This is
precisely what the TLS Pool does.  Towards the browser, it will speak in terms
of authenticated identities and, of course, network connection sockets.  This
suffices for the browser to make the authorisation choices that are usually
called for, so it appears to be a valid separation interface.

Similar separations apply for the user interfacing for PIN entry and local
identity selection; these popup from a separate interface, and are never related
to the browser.  This is a great help with keeping one’s system secure.
Moreover, in the old system there could be authentication popups from various
sources; a system built around the TLS Pool has a single interaction program to
talk to users, and is therefore easier to understand.
