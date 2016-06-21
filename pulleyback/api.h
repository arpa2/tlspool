// PulleyBack API, general specification:
//
// https://github.com/arpa2/steamworks/blob/master/docs/pulleyback-api.md
//
// From: Rick van Rein <rick@openfortress.nl>


#include <stdint.h>


// 
// 
// # Pulley Backend API
// 
// > *Pulley has a pluggable backend, where each plugin can be used to deliver
// > the tuples being added or deleted over a transaction.  The API below is
// > used to do just that, so it is implemented by backend plugins and used by
// > Pulley.*
// 
// 
// ## Plugins in the File System
// 
// Plugins are loadable dynamic objects; on POSIX systems, they will take the
// form of `.so` files, while on Windows they become so-called `.dll` files.
// 
// Plugins are loaded from a fixed directory, which helps packagers to construct
// packages with specific plugins; such packages would require Pulley to be
// installed and they would simply add the plugin to the said directory.
// 
// Though the storage directory for plugins may vary across distributions,
// we suggest to use `/usr/share/steamworks/pulleyback/` as a default.
// 
// ## Passing data to the Pulley Backend
// 
// Data passed to the backend follows the `der_t` type:

#include <stdint.h>
typedef uint8_t *der_t;

// There is no explicit length for the fields, because it only passes from
// Pulley to backend, and the Pulley retrieves data from LDAP where it is
// habitually verified to have proper DER encoding.  In other words, the
// `der_t` represents a single DER type with its self-descriptive length.
//   
// 
// ## Initialisation and Cleanup
// 
// Once the library is loaded, its dynamic symbols are resolved and can be
// invoked.  This is done through standard dynamic library support with
// `dlopen()`, `dlsym()` and `dlclose()`.  Some of the symbols may be
// optional, but only when explicitly noted in the text below.
// 
// Within the library, we can open any number of instances of a given backend,
// normally in response to corresponding lines in the Pulley Script.  The
// opening and closing calls for instances are:

void *pulleyback_open (int argc, char **argv, int varc);
void pulleyback_close (void *pbh);

// The `argc` and `argv` arguments to `pulleyback_open()` are similar in style
// to `main()`, where the values passed in come from the command line in the
// Pulley Script, and more specifically from the instantiation of the driver.
// The argument `varc` gives the number of variables that are passed to the
// driver for addition or removal of variables.  This number is mentioned
// explicitly to permit for error checking.  TODO:TYPING?
// The function returns a pulley-back handle as a pointer, or it returns NULL and
// sets `errno` to indicate failure.
// 
// The argument to `pulleyback_close()` is a pulley-back handle as obtained
// from `pulleyback_open()`.  In a proper program execution, every succeeded
// call to `pulleyback_open()` should be matched by one later call to
// `pulleyback_close()` and there should be no other invocations to the latter.
// 
// 
// ## Adding and Removing Forks
// 
// The primary function of a backend is to have forks added to and removed from
// an instance.  This is done with the respective functions

int pulleyback_add (void *pbh, uint8_t **forkdata);
int pulleyback_del (void *pbh, uint8_t **forkdata);

// These functions return 1 on success and 0 on failure; any failure status
// is retained within an instance, and reported for future additions and
// removals of forks, as well as for attempts to commit the transaction.
// Because none of the changes is made instantly, they are stored as part
// of a current transaction, which is always implicitly open.
// 
// The first parameter to the calls is an open pulley-back instance handle,
// the second
// points to an array of data fields describing the fork.  Guards are not
// passed down when they are not also mentioned as parameters, because they
// are handled inside Pulley.
// 
// Note that Pulley keeps track of the count of guards for a given set of
// `forkdata` values.  It will avoid invoking `pulleyback_add()` more than
// once on the same `forkdata` without first having called `pulleyback_del()`
// on it.  It will also avoid calling `pulleyback_del()` on `forkdata` values
// unless they have been added with `pulleyback_add()` and since not removed by
// `pulleyback_del()`.  These statements do apply over a sequence of sessions,
// each of which is marked by loading and unloading the backend plugin module.
// 
// The backend may assume that the `forkdata` contains as many non-NULL
// `der_t` as the number of variables promised to be supplied in `varc`
// during `pulleyback_open()`.
// 
// Finally, a call exists to clear out an entire database, so it can be
// filled from scratch:

int pulleyback_reset (void *pbh);

// This will result in all data being deleted, as part of the currently
// ongoing transaction.  Since this does not match what is being shown
// externally, it is possible to rebuild the database without glitches on
// the data that has not changed.  It can be a great help with error recovery
// and other resynchronisation operations.
// 
// 
// ## Transaction Processing Support
// 
// Transactions are used in the Pulley Backend to release all information
// at the same time.  This makes it possible, for instance, to remove something
// and add it again, without it disappearing from the external view.
// 
// Ideally, all backend plugins would have two-phase commit facilities, but
// not all underlying structures will be able to support this.  It is
// possible to achieve the same level of certainty with any number of
// two-phase and a single one-phase backend, so it is useful to detect
// a backend's support for two-phase commit.  We do this by checking if
// the dynamic symbol for prepare-to-commit resolves.
// 
// The following API functions support transactions on an open instance:

int pulleyback_prepare   (void *pbh);  /* OPTIONAL */
int pulleyback_commit    (void *pbh);
void pulleyback_rollback (void *pbh);

// The functions implement prepare-to-commit, commit and rollback, respectively.
// When only single-phase commit is supported, then `pulleback_prepare()` will
// not resolve, which is permitted as it is marked optional.  The result from
// `pulleyback_prepare()` predicts the success of an upcoming
// `pulleyback_commit()`, but still makes it possible to run
// `pulleyback_rollback()` instead.  When `pulleyback_prepare()` succeeds
// then the following `pulleyback_commit()` must also succeed; in fact, the
// calling application is under no obligation to check the result in that case.
// 
// The `pulleyback_prepare()` operation is idempotent, meaning that it is not
// problematic to invoke it once more; it will simply yield the same output.
// The `pulleyback_commit()` operation is also idempotent, and so is the
// `pulleyback_rollback()` operation.
// 
// When either `pulleyback_prepare()` or `pulleyback_commit()` fails, it
// sets `errno` to give an idea why.  It may specifically be useful to check
// for the `EAGAIN` value.  This is the designated return value in cases
// where a transaction runs into a deadlock.  In a single-threaded Pulley
// this should not happen, but it might in a multithreaded future version,
// and backends should already be prepared to inform such future versions
// with this special return value.
// 
// ## Normal Transactional Sequence
// 
// The normal Pulley sequence is to perform `pulleyback_prepare()` on all
// backends, and when all succeed to run `pulleyback_commit()` on them,
// and otherwise run `pulleyback_rollback()` on all of them.
// 
// It is permitted to invoke `pulleyback_rollback()` or `pulleyback_commit()`
// on an instance
// without prior call to `pulleback_prepare()`, in which case their outcome
// is effective immediately, and the update is done as atomically as possible.
// 
// It is not permitted to invoke anything but `pulleyback_close()`,
// `pulleyback_commit()` or `pulleyback_rollback()` on an instance
// after `pulleyback_prepare()` has been invoked.
// 
// Note that `pulleyback_close()` does an implicit `pulleyback_rollback()`
// on any outstanding changes.  Please do not rely on this though, it is
// only there as a stop-gap measure for unexpected program termination.
// 
// 
// ### Sharing Transactions between Backend Instances
// 
// Backends may support an addition function to support transactions that
// run over multiple instances of the same backend:

int pulleyback_collaborate   (void *pbh1, void *pbh2);

// This expresses an intent to use one transaction for the two backends.
// The return value is 1 for success and 0 for failure; the value `errno`
// will not be set upon failure, since it is something determined inside
// the implementation, possibly as a result of independent transactional
// scopes -- for example, separate database contexts or environments.
// 
// Upon success, an application only needs to end the transaction on
// `pbh1` or `pbh2`; doing it on both is superfluous but, in light of the
// idempotence of the transaction-ending operations, it is also harmless.
// 
// One way of using this is to maintain a list (or bitfield) with the backends
// that are involved in a transaction as a unique participant.  As soon as
// a new backend is added, use `pulleyback_collaborate()` to attempt to ask
// the new backend to collaborate with any of the existing transactions, until
// one succeeds.  Only when all collaboration attempts fail will the backend
// be added to the list (or bitfield) with the backends that are involved in
// a transaction as a unique participant.  When ending the transaction,
// invoke the operations only on the backends that are in this list (or bitfield).
// To implement this scheme, there probably is a need to also keep a list
// (or bitfield) of collaborators, just to make sure that it isn't asked to
// pair over and over again.
// 
// The implementation of this facility, as well as its grounds on which
// acceptance or rejection is formed, is entirely up to the backend.  This
// is why it is not optional -- it can easily return 0 in all cases, if it
// wants to.
// 
