/*
 * Chat for the TLS Tunnel tool is forked from Paul's PPP Daemon 2.4.7
 * of August 9th, 2014, on
 *   http://git.ozlabs.org/?p=ppp.git;a=summary
 *   https://github.com/paulusmack/ppp/
 * The adjoining manual page states:
 *   The "chat" program is in public domain. This is not the GNU public
 *   license. If it breaks then you get to keep both pieces.
 *
 * It has been embedded here for two reasons:
 *  - the original "chat" program assumes terminal / serial semantics
 *  - the original "chat" program is not scalable, it forks each connection
 *
 * From: Rick van Rein <rick@openfortress.nl>
 */

/*
 *	Chat -- a program for automatic session establishment (i.e. dial
 *		the phone and log in).
 *
 * Standard termination codes:
 *  0 - successful completion of the script
 *  1 - invalid argument, expect string too large, etc.
 *  2 - error on an I/O operation or fatal error condition.
 *  3 - timeout waiting for a simple string.
 *  4 - the first string declared as "ABORT"
 *  5 - the second string declared as "ABORT"
 *  6 - ... and so on for successive ABORT strings.
 *
 *	This software is in the public domain.
 *
 * -----------------
 *	22-May-99 added environment substitutuion, enabled with -E switch.
 *	Andreas Arens <andras@cityweb.de>.
 *
 *	12-May-99 added a feature to read data to be sent from a file,
 *	if the send string starts with @.  Idea from gpk <gpk@onramp.net>.
 *
 *	added -T and -U option and \T and \U substitution to pass a phone
 *	number into chat script. Two are needed for some ISDN TA applications.
 *	Keith Dart <kdart@cisco.com>
 *	
 *
 *	Added SAY keyword to send output to stderr.
 *      This allows to turn ECHO OFF and to output specific, user selected,
 *      text to give progress messages. This best works when stderr
 *      exists (i.e.: pppd in nodetach mode).
 *
 * 	Added HANGUP directives to allow for us to be called
 *      back. When HANGUP is set to NO, chat will not hangup at HUP signal.
 *      We rely on timeouts in that case.
 *
 *      Added CLR_ABORT to clear previously set ABORT string. This has been
 *      dictated by the HANGUP above as "NO CARRIER" (for example) must be
 *      an ABORT condition until we know the other host is going to close
 *      the connection for call back. As soon as we have completed the
 *      first stage of the call back sequence, "NO CARRIER" is a valid, non
 *      fatal string. As soon as we got called back (probably get "CONNECT"),
 *      we should re-arm the ABORT "NO CARRIER". Hence the CLR_ABORT command.
 *      Note that CLR_ABORT packs the abort_strings[] array so that we do not
 *      have unused entries not being reclaimed.
 *
 *      In the same vein as above, added CLR_REPORT keyword.
 *
 *      Allow for comments. Line starting with '#' are comments and are
 *      ignored. If a '#' is to be expected as the first character, the 
 *      expect string must be quoted.
 *
 *
 *		Francis Demierre <Francis@SwissMail.Com>
 * 		Thu May 15 17:15:40 MET DST 1997
 *
 *
 *      Added -r "report file" switch & REPORT keyword.
 *              Robert Geer <bgeer@xmission.com>
 *
 *      Added -s "use stderr" and -S "don't use syslog" switches.
 *              June 18, 1997
 *              Karl O. Pinc <kop@meme.com>
 *
 *
 *	Added -e "echo" switch & ECHO keyword
 *		Dick Streefland <dicks@tasking.nl>
 *
 *
 *	Considerable updates and modifications by
 *		Al Longyear <longyear@pobox.com>
 *		Paul Mackerras <paulus@cs.anu.edu.au>
 *
 *
 *	The original author is:
 *
 *		Karl Fox <karl@MorningStar.Com>
 *		Morning Star Technologies, Inc.
 *		1760 Zollinger Road
 *		Columbus, OH  43221
 *		(614)451-1883
 *
 */

#ifndef __STDC__
#define const
#endif

#ifndef lint
static const char rcsid[] = "$Id: chat.c,v 1.30 2004/01/17 05:47:55 carlsonj Exp $";
#endif

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <setjmp.h>

#define	STR_LEN	1024

#undef __P
#undef __V

#ifdef __STDC__
#include <stdarg.h>
#define __V(x)	x
#define __P(x)	x
#else
#include <varargs.h>
#define __V(x)	(va_alist) va_dcl
#define __P(x)	()
#define const
#endif

#ifndef O_NONBLOCK
#define O_NONBLOCK	O_NDELAY
#endif

#ifdef SUNOS
extern int sys_nerr;
extern char *sys_errlist[];
#define memmove(to, from, n)	bcopy(from, to, n)
#define strerror(n)		((unsigned)(n) < sys_nerr? sys_errlist[(n)] :\
				 "unknown error")
#endif

/*************** Micro getopt() *********************************************/
#define OPTSTATE()	int _O = 0;
#define	OPTION(c,v)	(_O&2&&**v?*(*v)++:!c||_O&4?0:(!(_O&1)&& \
				(--c,++v),_O=4,c&&**v=='-'&&v[0][1]?*++*v=='-'\
				&&!v[0][1]?(--c,++v,0):(_O=2,*(*v)++):0))
#define	OPTARG(c,v)	(_O&2?**v||(++v,--c)?(_O=1,--c,*v++): \
				(_O=4,(char*)0):(char*)0)
#define	OPTONLYARG(c,v)	(_O&2&&**v?(_O=1,--c,*v++):(char*)0)
#define	ARG(c,v)	(c?(--c,*v++):(char*)0)

/*************** Micro getopt() *********************************************/

#define	MAX_ABORTS		50
#define	MAX_REPORTS		50
#define	DEFAULT_CHAT_TIMEOUT	45

struct chatstate {
	jmp_buf jmp_exit;

	int plainfd;

	char *program_name;

	int terminating;

	int echo;
	int verbose;
	int to_log;	/* initialised to 1 */
	int to_stderr;
	int Verbose;
	int quiet;
	int report;
	int use_env;
	int exit_code;
	FILE* report_fp;
	char *report_file;
	char *chat_file;
	char *phone_num;
	char *phone_num2;
	int timeout;

	char *abort_string[MAX_ABORTS];
	char *fail_reason;
	char fail_buffer[50];
	int n_aborts;
	int abort_next;
	int timeout_next;
	int echo_next;
	int clear_abort_next;

	char *report_string[MAX_REPORTS];
	char  report_buffer[256];
	int n_reports;
	int report_next;
	int report_gathering;
	int clear_report_next;

	int say_next;
	int hup_next;

};

void *dup_mem __P((struct chatstate*,void *b, size_t c));
void *copy_of __P((struct chatstate*,char *s));
char *grow __P((struct chatstate*,char *s, char **p, size_t len));
void usage __P((struct chatstate*));
void msgf __P((struct chatstate*,const char *fmt, ...));
void fatal __P((struct chatstate*,int code, const char *fmt, ...));
void echo_stderr __P((struct chatstate*,int));
void terminate __P((struct chatstate*,int status));
void do_file __P((struct chatstate*,char *chat_file));
int  get_string __P((struct chatstate*,register char *string));
int  put_string __P((struct chatstate*,register char *s));
int  write_char __P((struct chatstate*,int c));
int  put_char __P((struct chatstate*,int c));
int  get_char __P((struct chatstate*));
void chat_send __P((struct chatstate*,register char *s));
char *character __P((int c));
void chat_expect __P((struct chatstate*,register char *s));
char *clean __P((struct chatstate*,register char *s, int sending));
void terminate __P((struct chatstate*,int status));
void pack_array __P((char **array, int end));
char *expect_strtok __P((char *, char *));
int vfmtmsg __P((char *, int, const char *, va_list));	/* vsprintf++ */

int chat __P((int, int, int, char *[]));

void *dup_mem(cs,b, c)
struct chatstate *cs;
void *b;
size_t c;
{
    void *ans = malloc (c);
    if (!ans)
	fatal(cs,2, "memory error!");

    memcpy (ans, b, c);
    return ans;
}

void *copy_of (cs,s)
struct chatstate *cs;
char *s;
{
    return dup_mem (cs, s, strlen (s) + 1);
}

/* grow a char buffer and keep a pointer offset */
char *grow(cs,s, p, len)
struct chatstate *cs;
char *s;
char **p;
size_t len;
{
    size_t l = *p - s;		/* save p as distance into s */

    s = realloc(s, len);
    if (!s)
	fatal(cs,2, "memory error!");
    *p = s + l;			/* restore p */
    return s;
}

/*
 * chat [ -v ] [ -E ] [ -T number ] [ -U number ] [ -t timeout ] [ -f chat-file ] \
 * [ -r report-file ] \
 *		[...[[expect[-say[-expect...]] say expect[-say[-expect]] ...]]]
 *
 *	Perform a UUCP-dialer-like chat script on stdin and stdout.
 */
int
chat_builtin (plainfd, progpath, argc, argv)
     int plainfd;
     char *progpath;
     int argc;
     char **argv;
{
    struct chatstate cs;
    int option;
    char *arg;
    OPTSTATE();

    /* Initialise "global" variables */
    memset (&cs, 0, sizeof (cs));
    cs.to_log = 1;
    cs.plainfd = plainfd;
    if (setjmp (cs.jmp_exit)) {
	return cs.exit_code;
    }

    cs.program_name = strrchr (progpath, '/');
    if (cs.program_name != NULL) {
	cs.program_name++;
    } else {
	cs.program_name = progpath;
    }
    tzset();

    while ((option = OPTION(argc, argv)) != 0) {
	switch (option) {
	case 'e':
	    ++cs.echo;
	    break;

	case 'E':
	    ++cs.use_env;
	    break;

	case 'v':
	    ++cs.verbose;
	    break;

	case 'V':
	    ++cs.Verbose;
	    break;

	case 's':
	    ++cs.to_stderr;
	    break;

	case 'S':
	    cs.to_log = 0;
	    break;

	case 'f':
	    if ((arg = OPTARG(argc, argv)) != NULL)
		    cs.chat_file = copy_of(&cs,arg);
	    else
		usage(&cs);
	    break;

	case 't':
	    if ((arg = OPTARG(argc, argv)) != NULL)
		cs.timeout = atoi(arg);
	    else
		usage(&cs);
	    break;

	case 'r':
	    arg = OPTARG (argc, argv);
	    if (arg) {
		if (cs.report_fp != NULL)
		    fclose (cs.report_fp);
		cs.report_file = copy_of (&cs,arg);
		cs.report_fp   = fopen (cs.report_file, "a");
		if (cs.report_fp != NULL) {
		    if (cs.verbose)
			fprintf (cs.report_fp, "Opening \"%s\"...\n",
				 cs.report_file);
		    cs.report = 1;
		}
	    }
	    break;

	case 'T':
	    if ((arg = OPTARG(argc, argv)) != NULL)
		cs.phone_num = copy_of(&cs,arg);
	    else
		usage(&cs);
	    break;

	case 'U':
	    if ((arg = OPTARG(argc, argv)) != NULL)
		cs.phone_num2 = copy_of(&cs,arg);
	    else
		usage(&cs);
	    break;

	default:
	    usage(&cs);
	    break;
	}
    }
/*
 * Default the report file to the stderr location
 */
    if (cs.report_fp == NULL)
	cs.report_fp = stderr;

    if (cs.to_log) {
#ifdef ultrix
	openlog("chat", LOG_PID);
#else
	openlog("chat", LOG_PID | LOG_NDELAY, LOG_LOCAL2);

	if (cs.verbose)
	    setlogmask(LOG_UPTO(LOG_INFO));
	else
	    setlogmask(LOG_UPTO(LOG_WARNING));
#endif
    }

    if (cs.chat_file != NULL) {
	arg = ARG(argc, argv);
	if (arg != NULL)
	    usage(&cs);
	else
	    do_file (&cs,cs.chat_file);
    } else {
	while ((arg = ARG(argc, argv)) != NULL) {
	    chat_expect(&cs,arg);

	    if ((arg = ARG(argc, argv)) != NULL)
		chat_send(&cs,arg);
	}
    }

    terminate(&cs,0);
    return 0;
}

/*
 *  Process a chat script when read from a file.
 */

void do_file (cs,chat_file)
struct chatstate *cs;
char *chat_file;
{
    int linect, sendflg;
    char *sp, *arg, quote;
    char buf [STR_LEN];
    FILE *cfp;

    cfp = fopen (chat_file, "r");
    if (cfp == NULL)
	fatal(cs,1, "%s -- open failed: %m", chat_file);

    linect = 0;
    sendflg = 0;

    while (fgets(buf, STR_LEN, cfp) != NULL) {
	sp = strchr (buf, '\n');
	if (sp)
	    *sp = '\0';

	linect++;
	sp = buf;

        /* lines starting with '#' are comments. If a real '#'
           is to be expected, it should be quoted .... */
        if ( *sp == '#' )
	    continue;

	while (*sp != '\0') {
	    if (*sp == ' ' || *sp == '\t') {
		++sp;
		continue;
	    }

	    if (*sp == '"' || *sp == '\'') {
		quote = *sp++;
		arg = sp;
		while (*sp != quote) {
		    if (*sp == '\0')
			fatal(cs,1, "unterminated quote (line %d)", linect);

		    if (*sp++ == '\\') {
			if (*sp != '\0')
			    ++sp;
		    }
		}
	    }
	    else {
		arg = sp;
		while (*sp != '\0' && *sp != ' ' && *sp != '\t')
		    ++sp;
	    }

	    if (*sp != '\0')
		*sp++ = '\0';

	    if (sendflg)
		chat_send (cs,arg);
	    else
		chat_expect (cs,arg);
	    sendflg = !sendflg;
	}
    }
    fclose (cfp);
}

/*
 *	We got an error parsing the command line.
 */
void usage(cs)
    struct chatstate *cs;
{
    fprintf(stderr, "\
Usage: %s ... -- [-e] [-E] [-v] [-V] [-t timeout] [-r report-file]\n\
     [-T phone-number] [-U phone-number2] {-f chat-file | chat-script}\n", cs->program_name);
    exit(1);
}

char line[1024];

/*
 * Send a message to syslog and/or stderr.
 */
void msgf __V((struct chatstate *cs,const char *fmt, ...))
{
    va_list args;

#ifdef __STDC__
    va_start(args, fmt);
#else
    char *fmt;
    va_start(args);
    fmt = va_arg(args, char *);
#endif

    vfmtmsg(line, sizeof(line), fmt, args);
    if (cs->to_log)
	syslog(LOG_INFO, "%s", line);
    if (cs->to_stderr)
	fprintf(stderr, "%s\n", line);
}

/*
 *	Print an error message and terminate.
 */

void fatal __V((struct chatstate *cs,int code, const char *fmt, ...))
{
    va_list args;

#ifdef __STDC__
    va_start(args, fmt);
#else
    int code;
    char *fmt;
    va_start(args);
    code = va_arg(args, int);
    fmt = va_arg(args, char *);
#endif

    vfmtmsg(line, sizeof(line), fmt, args);
    if (cs->to_log)
	syslog(LOG_ERR, "%s", line);
    if (cs->to_stderr)
	fprintf(stderr, "%s\n", line);
    terminate(cs,code);
}

void terminate(cs,status)
struct chatstate *cs;
int status;
{

    if (cs->terminating) {
	cs->exit_code = status;
	longjmp (cs->jmp_exit, 1);
     }
    cs->terminating = 1;
    echo_stderr(cs, -1);
/*
 * Allow the last of the report string to be gathered before we terminate.
 */
    if (cs->report_gathering) {
	int c, rep_len;

	rep_len = strlen(cs->report_buffer);
	while (rep_len + 1 <= sizeof(cs->report_buffer)) {
	    c = get_char(cs);
	    if (c < 0 || iscntrl(c))
		break;
	    cs->report_buffer[rep_len] = c;
	    ++rep_len;
	}
	cs->report_buffer[rep_len] = 0;
	fprintf (cs->report_fp, "chat:  %s\n", cs->report_buffer);
    }
    if (cs->report_file != (char *) 0 && cs->report_fp != (FILE *) NULL) {
	if (cs->verbose)
	    fprintf (cs->report_fp, "Closing \"%s\".\n", cs->report_file);
	fclose (cs->report_fp);
	cs->report_fp = (FILE *) NULL;
    }

    cs->exit_code = status;
    longjmp (cs->jmp_exit, 1);
}

/*
 *	'Clean up' this string.
 */
char *clean(cs, s, sending)
struct chatstate *cs;
register char *s;
int sending;  /* set to 1 when sending (putting) this string. */
{
    char cur_chr;
    char *s1, *p, *phchar;
    int add_return = sending;
    size_t len = strlen(s) + 3;		/* see len comments below */

#define isoctal(chr)	(((chr) >= '0') && ((chr) <= '7'))
#define isalnumx(chr)	((((chr) >= '0') && ((chr) <= '9')) \
			 || (((chr) >= 'a') && ((chr) <= 'z')) \
			 || (((chr) >= 'A') && ((chr) <= 'Z')) \
			 || (chr) == '_')

    p = s1 = malloc(len);
    if (!p)
	fatal(cs,2, "memory error!");
    while (*s) {
	cur_chr = *s++;
	if (cur_chr == '^') {
	    cur_chr = *s++;
	    if (cur_chr == '\0') {
		*p++ = '^';
		break;
	    }
	    cur_chr &= 0x1F;
	    if (cur_chr != 0) {
		*p++ = cur_chr;
	    }
	    continue;
	}

	if (cs->use_env && cur_chr == '$') {		/* ARI */
	    char c;

	    phchar = s;
	    while (isalnumx(*s))
		s++;
	    c = *s;		/* save */
	    *s = '\0';
	    phchar = getenv(phchar);
	    *s = c;		/* restore */
	    if (phchar) {
		len += strlen(phchar);
		s1 = grow(cs,s1, &p, len);
		while (*phchar)
		    *p++ = *phchar++;
	    }
	    continue;
	}

	if (cur_chr != '\\') {
	    *p++ = cur_chr;
	    continue;
	}

	cur_chr = *s++;
	if (cur_chr == '\0') {
	    if (sending) {
		*p++ = '\\';
		*p++ = '\\';	/* +1 for len */
	    }
	    break;
	}

	switch (cur_chr) {
	case 'b':
	    *p++ = '\b';
	    break;

	case 'c':
	    if (sending && *s == '\0')
		add_return = 0;
	    else
		*p++ = cur_chr;
	    break;

	case '\\':
	case 'K':
	case 'p':
	case 'd':
	    if (sending)
		*p++ = '\\';
	    *p++ = cur_chr;
	    break;

	case 'T':
	    if (sending && cs->phone_num) {
		len += strlen(cs->phone_num);
		s1 = grow(cs, s1, &p, len);
		for (phchar = cs->phone_num; *phchar != '\0'; phchar++) 
		    *p++ = *phchar;
	    }
	    else {
		*p++ = '\\';
		*p++ = 'T';
	    }
	    break;

	case 'U':
	    if (sending && cs->phone_num2) {
		len += strlen(cs->phone_num2);
		s1 = grow(cs, s1, &p, len);
		for (phchar = cs->phone_num2; *phchar != '\0'; phchar++) 
		    *p++ = *phchar;
	    }
	    else {
		*p++ = '\\';
		*p++ = 'U';
	    }
	    break;

	case 'q':
	    cs->quiet = 1;
	    break;

	case 'r':
	    *p++ = '\r';
	    break;

	case 'n':
	    *p++ = '\n';
	    break;

	case 's':
	    *p++ = ' ';
	    break;

	case 't':
	    *p++ = '\t';
	    break;

	case 'N':
	    if (sending) {
		*p++ = '\\';
		*p++ = '\0';
	    }
	    else
		*p++ = 'N';
	    break;

	case '$':			/* ARI */
	    if (cs->use_env) {
		*p++ = cur_chr;
		break;
	    }
	    /* FALL THROUGH */

	default:
	    if (isoctal (cur_chr)) {
		cur_chr &= 0x07;
		if (isoctal (*s)) {
		    cur_chr <<= 3;
		    cur_chr |= *s++ - '0';
		    if (isoctal (*s)) {
			cur_chr <<= 3;
			cur_chr |= *s++ - '0';
		    }
		}

		if (cur_chr != 0 || sending) {
		    if (sending && (cur_chr == '\\' || cur_chr == 0))
			*p++ = '\\';
		    *p++ = cur_chr;
		}
		break;
	    }

	    if (sending)
		*p++ = '\\';
	    *p++ = cur_chr;
	    break;
	}
    }

    if (add_return)
	*p++ = '\r';	/* +2 for len */

    *p = '\0';		/* +3 for len */
    return s1;
}

/*
 * A modified version of 'strtok'. This version skips \ sequences.
 */

char *expect_strtok (s, term)
     char *s, *term;
{
    static  char *str   = "";
    int	    escape_flag = 0;
    char   *result;

/*
 * If a string was specified then do initial processing.
 */
    if (s)
	str = s;

/*
 * If this is the escape flag then reset it and ignore the character.
 */
    if (*str)
	result = str;
    else
	result = (char *) 0;

    while (*str) {
	if (escape_flag) {
	    escape_flag = 0;
	    ++str;
	    continue;
	}

	if (*str == '\\') {
	    ++str;
	    escape_flag = 1;
	    continue;
	}

/*
 * If this is not in the termination string, continue.
 */
	if (strchr (term, *str) == (char *) 0) {
	    ++str;
	    continue;
	}

/*
 * This is the terminator. Mark the end of the string and stop.
 */
	*str++ = '\0';
	break;
    }
    return (result);
}

/*
 * Process the expect string
 */

void chat_expect (cs,s)
struct chatstate *cs;
char *s;
{
    char *expect;
    char *reply;

    if (strcmp(s, "HANGUP") == 0) {
	++cs->hup_next;
        return;
    }
 
    if (strcmp(s, "ABORT") == 0) {
	++cs->abort_next;
	return;
    }

    if (strcmp(s, "CLR_ABORT") == 0) {
	++cs->clear_abort_next;
	return;
    }

    if (strcmp(s, "REPORT") == 0) {
	++cs->report_next;
	return;
    }

    if (strcmp(s, "CLR_REPORT") == 0) {
	++cs->clear_report_next;
	return;
    }

    if (strcmp(s, "TIMEOUT") == 0) {
	++cs->timeout_next;
	return;
    }

    if (strcmp(s, "ECHO") == 0) {
	++cs->echo_next;
	return;
    }

    if (strcmp(s, "SAY") == 0) {
	++cs->say_next;
	return;
    }

/*
 * Fetch the expect and reply string.
 */
    for (;;) {
	expect = expect_strtok (s, "-");
	s      = (char *) 0;

	if (expect == (char *) 0)
	    return;

	reply = expect_strtok (s, "-");

/*
 * Handle the expect string. If successful then exit.
 */
	if (get_string (cs,expect))
	    return;

/*
 * If there is a sub-reply string then send it. Otherwise any condition
 * is terminal.
 */
	if (reply == (char *) 0 || cs->exit_code != 3)
	    break;

	chat_send (cs, reply);
    }

/*
 * The expectation did not occur. This is terminal.
 */
    if (cs->fail_reason)
	msgf(cs,"Failed (%s)", cs->fail_reason);
    else
	msgf(cs,"Failed");
    terminate(cs,cs->exit_code);
}

/*
 * Translate the input character to the appropriate string for printing
 * the data.
 */

char *character(c)
int c;
{
    static char string[10];
    char *meta;

    meta = (c & 0x80) ? "M-" : "";
    c &= 0x7F;

    if (c < 32)
	sprintf(string, "%s^%c", meta, (int)c + '@');
    else if (c == 127)
	sprintf(string, "%s^?", meta);
    else
	sprintf(string, "%s%c", meta, c);

    return (string);
}

/*
 *  process the reply string
 */
void chat_send (cs,s)
struct chatstate *cs;
register char *s;
{
    char file_data[STR_LEN];

    if (cs->say_next) {
	cs->say_next = 0;
	s = clean(cs, s, 1);
	write(2, s, strlen(s));
        free(s);
	return;
    }

    if (cs->hup_next) {
        cs->hup_next = 0;
	/* silently ignore HUP: if (strcmp(s, "OFF") == 0) ...*/
        signal(SIGHUP, SIG_IGN);
        return;
    }

    if (cs->echo_next) {
	cs->echo_next = 0;
	cs->echo = (strcmp(s, "ON") == 0);
	return;
    }

    if (cs->abort_next) {
	char *s1;
	
	cs->abort_next = 0;
	
	if (cs->n_aborts >= MAX_ABORTS)
	    fatal(cs,2, "Too many ABORT strings");
	
	s1 = clean(cs, s, 0);
	
	if (strlen(s1) > strlen(s)
	    || strlen(s1) + 1 > sizeof(cs->fail_buffer))
	    fatal(cs,1, "Illegal or too-long ABORT string ('%v')", s);

	cs->abort_string[cs->n_aborts++] = s1;

	if (cs->verbose)
	    msgf(cs,"abort on (%v)", s);
	return;
    }

    if (cs->clear_abort_next) {
	char *s1;
	int   i;
        int   old_max;
	int   pack = 0;
	
	cs->clear_abort_next = 0;
	
	s1 = clean(cs, s, 0);
	
	if (strlen(s1) > strlen(s)
	    || strlen(s1) + 1 > sizeof(cs->fail_buffer))
	    fatal(cs,1, "Illegal or too-long CLR_ABORT string ('%v')", s);

        old_max = cs->n_aborts;
	for (i=0; i < cs->n_aborts; i++) {
	    if ( strcmp(s1,cs->abort_string[i]) == 0 ) {
		free(cs->abort_string[i]);
		cs->abort_string[i] = NULL;
		pack++;
		cs->n_aborts--;
		if (cs->verbose)
		    msgf(cs,"clear abort on (%v)", s);
	    }
	}
        free(s1);
	if (pack)
	    pack_array(cs->abort_string,old_max);
	return;
    }

    if (cs->report_next) {
	char *s1;
	
	cs->report_next = 0;
	if (cs->n_reports >= MAX_REPORTS)
	    fatal(cs,2, "Too many REPORT strings");
	
	s1 = clean(cs, s, 0);
	if (strlen(s1) > strlen(s)
	    || strlen(s1) + 1 > sizeof(cs->fail_buffer))
	    fatal(cs,1, "Illegal or too-long REPORT string ('%v')", s);
	
	cs->report_string[cs->n_reports++] = s1;
	
	if (cs->verbose)
	    msgf(cs,"report (%v)", s);
	return;
    }

    if (cs->clear_report_next) {
	char *s1;
	int   i;
	int   old_max;
	int   pack = 0;
	
	cs->clear_report_next = 0;
	
	s1 = clean(cs, s, 0);
	
	if (strlen(s1) > strlen(s)
	    || strlen(s1) + 1 > sizeof(cs->fail_buffer))
	    fatal(cs,1, "Illegal or too-long REPORT string ('%v')", s);

	old_max = cs->n_reports;
	for (i=0; i < cs->n_reports; i++) {
	    if ( strcmp(s1,cs->report_string[i]) == 0 ) {
		free(cs->report_string[i]);
		cs->report_string[i] = NULL;
		pack++;
		cs->n_reports--;
		if (cs->verbose)
		    msgf(cs,"clear report (%v)", s);
	    }
	}
        free(s1);
        if (pack)
	    pack_array(cs->report_string,old_max);
	
	return;
    }

    if (cs->timeout_next) {
	cs->timeout_next = 0;
	s = clean(cs, s, 0);
	cs->timeout = atoi(s);
	
	if (cs->timeout <= 0)
	    cs->timeout = DEFAULT_CHAT_TIMEOUT;

	if (cs->verbose)
	    msgf(cs,"timeout set to %d seconds", cs->timeout);

	return;
    }

    /*
     * The syntax @filename means read the string to send from the
     * file `filename'.
     */
    if (s[0] == '@') {
	/* skip the @ and any following white-space */
	char *fn = s;
	while (*++fn == ' ' || *fn == '\t')
	    ;

	if (*fn != 0) {
	    FILE *f;
	    int n = 0;

	    /* open the file and read until STR_LEN-1 bytes or end-of-file */
	    f = fopen(fn, "r");
	    if (f == NULL)
		fatal(cs,1, "%s -- open failed: %m", fn);
	    while (n < STR_LEN - 1) {
		int nr = fread(&file_data[n], 1, STR_LEN - 1 - n, f);
		if (nr < 0)
		    fatal(cs,1, "%s -- read error", fn);
		if (nr == 0)
		    break;
		n += nr;
	    }
	    fclose(f);

	    /* use the string we got as the string to send,
	       but trim off the final newline if any. */
	    if (n > 0 && file_data[n-1] == '\n')
		--n;
	    file_data[n] = 0;
	    s = file_data;
	}
    }

    if (strcmp(s, "EOT") == 0)
	s = "^D\\c";
    else if (strcmp(s, "BREAK") == 0)
	s = "\\K\\c";

    if (!put_string(cs, s))
	fatal(cs,1, "Failed");
}

int get_char(cs)
struct chatstate *cs;
{
    int status;
    char c;

    status = read(cs->plainfd, &c, 1);

    switch (status) {
    case 1:
	return ((int)c & 0x7F);

    default:
	msgf(cs,"warning: read() on stdin returned %d", status);

    case -1:
	if ((status = fcntl(0, F_GETFL, 0)) == -1)
	    fatal(cs,2, "Can't get file mode flags on stdin: %m");

	if (fcntl(0, F_SETFL, status & ~O_NONBLOCK) == -1)
	    fatal(cs,2, "Can't set file mode flags on stdin: %m");
	
	return (-1);
    }
}

int put_char(cs,c)
struct chatstate *cs;
int c;
{
    int status;
    char ch = c;

    usleep(10000);		/* inter-character typing delay (?) */

    status = write(cs->plainfd, &ch, 1);

    switch (status) {
    case 1:
	return (0);
	
    default:
	msgf(cs,"warning: write() on connection returned %d", status);
	
    case -1:
	if ((status = fcntl(0, F_GETFL, 0)) == -1)
	    fatal(cs,2, "Can't get file mode flags on stdin, %m");

	if (fcntl(0, F_SETFL, status & ~O_NONBLOCK) == -1)
	    fatal(cs,2, "Can't set file mode flags on stdin: %m");
	
	return (-1);
    }
}

int write_char (cs, c)
struct chatstate *cs;
int c;
{
    if (put_char(cs,c) < 0) {
	if (cs->verbose) {
	    if (errno == EINTR || errno == EWOULDBLOCK)
		msgf(cs," -- write timed out");
	    else
		msgf(cs," -- write failed: %m");
	}
	return (0);
    }
    return (1);
}

int put_string (cs,s)
struct chatstate *cs;
register char *s;
{
    cs->quiet = 0;
    s = clean(cs, s, 1);

    if (cs->verbose) {
	if (cs->quiet)
	    msgf(cs,"send (?????\?)");
	else
	    msgf(cs,"send (%v)", s);
    }

    while (*s) {
	register char c = *s++;

	if (c != '\\') {
	    if (!write_char (cs, c))
		return 0;
	    continue;
	}

	c = *s++;
	switch (c) {
	case 'd':
	    sleep(1);
	    break;

	case 'K':
	    /* Silently ignored: break_sequence(); */
	    break;

	case 'p':
	    usleep(10000); 	/* 1/100th of a second (arg is microseconds) */
	    break;

	default:
	    if (!write_char (cs,c))
		return 0;
	    break;
	}
    }

    return (1);
}

/*
 *	Echo a character to stderr.
 *	When called with -1, a '\n' character is generated when
 *	the cursor is not at the beginning of a line.
 */
void echo_stderr(cs, n)
struct chatstate *cs;
int n;
{
    static int need_lf;
    char *s;

    switch (n) {
    case '\r':		/* ignore '\r' */
	break;
    case -1:
	if (need_lf == 0)
	    break;
	/* fall through */
    case '\n':
	write(2, "\n", 1);
	need_lf = 0;
	break;
    default:
	s = character(n);
	write(2, s, strlen(s));
	need_lf = 1;
	break;
    }
}

/*
 *	'Wait for' this string to appear on this file descriptor.
 */
int get_string(cs, string)
struct chatstate *cs;
register char *string;
{
    char temp[STR_LEN];
    int c, printed = 0, len, minlen;
    register char *s = temp, *end = s + STR_LEN;
    char *logged = temp;

    cs->fail_reason = (char *)0;
    string = clean(cs, string, 0);
    len = strlen(string);
    minlen = (len > sizeof(cs->fail_buffer)? len: sizeof(cs->fail_buffer)) - 1;

    if (cs->verbose)
	msgf(cs,"expect (%v)", string);

    if (len > STR_LEN) {
	msgf(cs,"expect string is too long");
	cs->exit_code = 1;
	return 0;
    }

    if (len == 0) {
	if (cs->verbose)
	    msgf(cs,"got it");
	return (1);
    }

    while ( (c = get_char(cs)) >= 0) {
	int n, abort_len, report_len;

	if (cs->echo)
	    echo_stderr(cs, c);
	if (cs->verbose && c == '\n') {
	    if (s == logged)
		msgf(cs,"");	/* blank line */
	    else
		msgf(cs,"%0.*v", s - logged, logged);
	    logged = s + 1;
	}

	*s++ = c;

	if (cs->verbose && s >= logged + 80) {
	    msgf(cs,"%0.*v", s - logged, logged);
	    logged = s;
	}

	if (cs->Verbose) {
	   if (c == '\n')
	       fputc( '\n', stderr );
	   else if (c != '\r')
	       fprintf( stderr, "%s", character(c) );
	}

	if (!cs->report_gathering) {
	    for (n = 0; n < cs->n_reports; ++n) {
		if ((cs->report_string[n] != (char*) NULL) &&
		    s - temp >= (report_len = strlen(cs->report_string[n])) &&
		    strncmp(s - report_len, cs->report_string[n], report_len) == 0) {
		    time_t time_now   = time ((time_t*) NULL);
		    struct tm* tm_now = localtime (&time_now);

		    strftime (cs->report_buffer, 20, "%b %d %H:%M:%S ", tm_now);
		    strcat (cs->report_buffer, cs->report_string[n]);

		    cs->report_string[n] = (char *) NULL;
		    cs->report_gathering = 1;
		    break;
		}
	    }
	}
	else {
	    if (!iscntrl (c)) {
		int rep_len = strlen (cs->report_buffer);
		cs->report_buffer[rep_len]     = c;
		cs->report_buffer[rep_len + 1] = '\0';
	    }
	    else {
		cs->report_gathering = 0;
		fprintf (cs->report_fp, "chat:  %s\n", cs->report_buffer);
	    }
	}

	if (s - temp >= len &&
	    c == string[len - 1] &&
	    strncmp(s - len, string, len) == 0) {
	    if (cs->verbose) {
		if (s > logged)
		    msgf(cs,"%0.*v", s - logged, logged);
		msgf(cs," -- got it\n");
	    }

	    return (1);
	}

	for (n = 0; n < cs->n_aborts; ++n) {
	    if (s - temp >= (abort_len = strlen(cs->abort_string[n])) &&
		strncmp(s - abort_len, cs->abort_string[n], abort_len) == 0) {
		if (cs->verbose) {
		    if (s > logged)
			msgf(cs,"%0.*v", s - logged, logged);
		    msgf(cs," -- failed");
		}

		cs->exit_code = n + 4;
		strcpy(cs->fail_reason = cs->fail_buffer, cs->abort_string[n]);
		return (0);
	    }
	}

	if (s >= end) {
	    if (logged < s - minlen) {
		if (cs->verbose)
		    msgf(cs,"%0.*v", s - logged, logged);
		logged = s;
	    }
	    s -= minlen;
	    memmove(temp, s, minlen);
	    logged = temp + (logged - s);
	    s = temp + minlen;
	}

    }

    if (cs->verbose && printed) {
	msgf(cs," -- read failed: %m");
    }

    cs->exit_code = 3;
    return (0);
}

/*
 * Gross kludge to handle Solaris versions >= 2.6 having usleep.
 */
#ifdef SOL2
#include <sys/param.h>
#if MAXUID > 65536		/* then this is Solaris 2.6 or later */
#undef NO_USLEEP
#endif
#endif /* SOL2 */

#ifdef NO_USLEEP
#include <sys/types.h>
#include <sys/time.h>

/*
  usleep -- support routine for 4.2BSD system call emulations
  last edit:  29-Oct-1984     D A Gwyn
  */

extern int	  select();

int
usleep( usec )				  /* returns 0 if ok, else -1 */
    long		usec;		/* delay in microseconds */
{
    static struct {		/* `timeval' */
	long	tv_sec;		/* seconds */
	long	tv_usec;	/* microsecs */
    } delay;	    		/* _select() timeout */

    delay.tv_sec  = usec / 1000000L;
    delay.tv_usec = usec % 1000000L;

    return select(0, (long *)0, (long *)0, (long *)0, &delay);
}
#endif

void
pack_array (array, end)
    char **array; /* The address of the array of string pointers */
    int    end;   /* The index of the next free entry before CLR_ */
{
    int i, j;

    for (i = 0; i < end; i++) {
	if (array[i] == NULL) {
	    for (j = i+1; j < end; ++j)
		if (array[j] != NULL)
		    array[i++] = array[j];
	    for (; i < end; ++i)
		array[i] = NULL;
	    break;
	}
    }
}

/*
 * vfmtmsg - format a message into a buffer.  Like vsprintf except we
 * also specify the length of the output buffer, and we handle the
 * %m (error message) format.
 * Doesn't do floating-point formats.
 * Returns the number of chars put into buf.
 */
#define OUTCHAR(c)	(buflen > 0? (--buflen, *buf++ = (c)): 0)

int
vfmtmsg(buf, buflen, fmt, args)
    char *buf;
    int buflen;
    const char *fmt;
    va_list args;
{
    int c, i, n;
    int width, prec, fillch;
    int base, len, neg, quoted;
    unsigned long val = 0;
    char *str, *buf0;
    const char *f;
    unsigned char *p;
    char num[32];
    static char hexchars[] = "0123456789abcdef";

    buf0 = buf;
    --buflen;
    while (buflen > 0) {
	for (f = fmt; *f != '%' && *f != 0; ++f)
	    ;
	if (f > fmt) {
	    len = f - fmt;
	    if (len > buflen)
		len = buflen;
	    memcpy(buf, fmt, len);
	    buf += len;
	    buflen -= len;
	    fmt = f;
	}
	if (*fmt == 0)
	    break;
	c = *++fmt;
	width = prec = 0;
	fillch = ' ';
	if (c == '0') {
	    fillch = '0';
	    c = *++fmt;
	}
	if (c == '*') {
	    width = va_arg(args, int);
	    c = *++fmt;
	} else {
	    while (isdigit(c)) {
		width = width * 10 + c - '0';
		c = *++fmt;
	    }
	}
	if (c == '.') {
	    c = *++fmt;
	    if (c == '*') {
		prec = va_arg(args, int);
		c = *++fmt;
	    } else {
		while (isdigit(c)) {
		    prec = prec * 10 + c - '0';
		    c = *++fmt;
		}
	    }
	}
	str = 0;
	base = 0;
	neg = 0;
	++fmt;
	switch (c) {
	case 'd':
	    i = va_arg(args, int);
	    if (i < 0) {
		neg = 1;
		val = -i;
	    } else
		val = i;
	    base = 10;
	    break;
	case 'o':
	    val = va_arg(args, unsigned int);
	    base = 8;
	    break;
	case 'x':
	    val = va_arg(args, unsigned int);
	    base = 16;
	    break;
	case 'p':
	    val = (unsigned long) va_arg(args, void *);
	    base = 16;
	    neg = 2;
	    break;
	case 's':
	    str = va_arg(args, char *);
	    break;
	case 'c':
	    num[0] = va_arg(args, int);
	    num[1] = 0;
	    str = num;
	    break;
	case 'm':
	    str = strerror(errno);
	    break;
	case 'v':		/* "visible" string */
	case 'q':		/* quoted string */
	    quoted = c == 'q';
	    p = va_arg(args, unsigned char *);
	    if (fillch == '0' && prec > 0) {
		n = prec;
	    } else {
		n = strlen((char *)p);
		if (prec > 0 && prec < n)
		    n = prec;
	    }
	    while (n > 0 && buflen > 0) {
		c = *p++;
		--n;
		if (!quoted && c >= 0x80) {
		    OUTCHAR('M');
		    OUTCHAR('-');
		    c -= 0x80;
		}
		if (quoted && (c == '"' || c == '\\'))
		    OUTCHAR('\\');
		if (c < 0x20 || (0x7f <= c && c < 0xa0)) {
		    if (quoted) {
			OUTCHAR('\\');
			switch (c) {
			case '\t':	OUTCHAR('t');	break;
			case '\n':	OUTCHAR('n');	break;
			case '\b':	OUTCHAR('b');	break;
			case '\f':	OUTCHAR('f');	break;
			default:
			    OUTCHAR('x');
			    OUTCHAR(hexchars[c >> 4]);
			    OUTCHAR(hexchars[c & 0xf]);
			}
		    } else {
			if (c == '\t')
			    OUTCHAR(c);
			else {
			    OUTCHAR('^');
			    OUTCHAR(c ^ 0x40);
			}
		    }
		} else
		    OUTCHAR(c);
	    }
	    continue;
	default:
	    *buf++ = '%';
	    if (c != '%')
		--fmt;		/* so %z outputs %z etc. */
	    --buflen;
	    continue;
	}
	if (base != 0) {
	    str = num + sizeof(num);
	    *--str = 0;
	    while (str > num + neg) {
		*--str = hexchars[val % base];
		val = val / base;
		if (--prec <= 0 && val == 0)
		    break;
	    }
	    switch (neg) {
	    case 1:
		*--str = '-';
		break;
	    case 2:
		*--str = 'x';
		*--str = '0';
		break;
	    }
	    len = num + sizeof(num) - 1 - str;
	} else {
	    len = strlen(str);
	    if (prec > 0 && len > prec)
		len = prec;
	}
	if (width > 0) {
	    if (width > buflen)
		width = buflen;
	    if ((n = width - len) > 0) {
		buflen -= n;
		for (; n > 0; --n)
		    *buf++ = fillch;
	    }
	}
	if (len > buflen)
	    len = buflen;
	memcpy(buf, str, len);
	buf += len;
	buflen -= len;
    }
    *buf = 0;
    return buf - buf0;
}
