/* tlspool/cache.c -- Caching authn/authz results in memcached */

/*
 * CACHING BASED ON KEY STRUCTURES
 *
 * The lookup keys used with memcached are textual, so as to simplify
 * their administration.  The values however, are usually binary.
 *
 * The key structure is:
 *   <package> <task> <id_remote>[ <id_local>]
 *
 * Concrete examples of keys:
 *   tlspool authn rick@example.com michiel@example.com
 *   tlspool authn example.com
 *   tlspool authz rick@example.com michiel@example.com
 *
 * Of course, authn indicates authentication and authz is authorization.
 * The <id_remote> indicates the host or user@host for the remote party
 * and inasfar as it is needed, a space and the <id_local> is added to
 * detail under what local identity the remote was welcomed or rejected.
 * The form with a <local_id> is more specific, so it overrides the
 * form without it.  This means that one should first look for the
 * form with, stop when something is found, and otherwise continue to
 * the form without.  But only if both forms make sense to an authn or
 * authz application, of course.
 *
 * While authn'ing or authz'ing, the key is constructed as soon as
 * possible, so any cache hit can be found as soon as possible.
 */

 #include "whoami.h"

