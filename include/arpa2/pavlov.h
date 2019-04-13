
/* Main interaction point: pavlov () with parameters:
 *
 *  - fdin, fdout --> file descriptors for input/output streams
 *  - progname, argc, argv  --> as in main, but argv[0] consumed into progname
 *
 * The return value is like a value for exit() -- 0 for ok, or 1 with errno.
 *
 * Commands start from argv[0] and contain, among others:
 *
 *   - !<data> --> send out the data
 *   - ?<regex> --> receive >0 bytes and recognise the POSIX extended regex
 *   - @<msdelay> --> delay in milli-seconds
 */
int pavlov (int fdin, int fdout,
		char *progname, int argc, char *argv[]);
