#include <stddef.h>

size_t __cdecl strnlen( const char *start, size_t maxlen )
{
  /* Determine the length of a NUL terminated string, subject
   * to a maximum permitted length constraint.
   */
  const char *stop = start;

  /* Scan at most maxlen bytes, seeking a NUL terminator;
   * note that we MUST enforce the length check, BEFORE the
   * terminator check, otherwise we could scan maxlen + 1
   * bytes, which POSIX forbids.
   */
  while( ((stop - start) < maxlen) && *stop )
    ++stop;

  /* Result is the number of non-NUL bytes actually scanned.
   */
  return stop - start;
}

