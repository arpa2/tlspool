/* This is the chat module's API call.  Use argc and argv as in main(),
 * but set progpath to (a variant of) argv[0] as desired.  The plainfd
 * is the bidirectional channel (usually a socket) supporting read()
 * and write() operatiorns.
 */

/*
 * chat [ -v ] [ -E ] [ -T number ] [ -U number ] [ -t timeout ] [ -f chat-file ] \
 * [ -r report-file ] \
 *		[...[[expect[-say[-expect...]] say expect[-say[-expect]] ...]]]
 *
 *	Perform a UUCP-dialer-like chat script on stdin and stdout.
 */
int chat_builtin (int plainfd, char *progpath, int argc, char *argv []);
