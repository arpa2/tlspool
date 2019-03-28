/* validate.c -- Validation expression processing framework */


#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <assert.h>

#include <syslog.h>

#ifndef WINDOWS_PORT
#include <unistd.h>
#endif /* WINDOWS_PORT */

#include <tlspool/internal.h>


#ifdef DEBUG
#   include <pthread.h>
#endif


/* We have a total of 28 validation variables, counting the uppercase and
 * lowercase variations separately.  This excludes the logical operators
 * and the logical constants 1 and 0, which will be handled in the code
 * for calculation of validation expressions.
 *
 * The following table will be setup during valexp_setup to map a letter
 * to its corresponding bit number valexpreqs_t based on the table below;
 * thanks to the limited number of variables, the size of this variable
 * can be limited to 32 bits only.
 */
static char valexp_varchars [] = "LlIiFfAaTtDdRrEeOoGgPpUuSsCcQq";
static int valexp_char_bitnum [128];
typedef uint32_t valexpreqs_t;

#define VALEXP_CHARBIT(c)  (valexp_char_bitnum [(c)])
#define VALEXP_CHARKNOWN(c) (((c) >= 0) && ((c) <= 127) && (VALEXP_CHARBIT((c)) >= 0))
#define VALEXP_OPERAND(c) (((c) == '0') || ((c) == '1') || (VALEXP_CHARKNOWN((c))))
#define VALEXP_SETBIT(b,w)   ((w) |=   (1 << (b)))
#define VALEXP_RESETBIT(b,w) ((w) &= ~ (1 << (b)))
#define VALEXP_ISSET(b,w)    ((w) &    (1 << (b)))
#define VALEXP_EMPTY(w)      ((w) == (uint32_t) 0)


/* One alternative path to truth, or "case", in a validation expression.
 *
 * As a special case, zyx? expands to zx&zx~&yz&|| where the surprise may
 * be that the expression is also true the two alternatives y and z are both
 * true; this is an optimisation that may lead to faster results.  Note
 * that negation over this structure will has no impact on the condition,
 * x, but instead modifies the two alternatives, y and z.
 *
 * The "case" has a "compute" bitset that quickly shows if more work is
 * needed on the case. Once no bits show a result to be computed, the
 * corresponding case is complete, and a final result can be computed
 * for that case.  If the final result is positive, then the entire
 * validation expression returns a positive result, even if other cases
 * still have outstanding work.
 *
 * The "positive" and "negative" bitsets indicate requirements of a
 * positive or negative outcome, respectively.  When an outcome is TRUE,
 * the corresponding "positive" bit is cleared; when an outcome if FALSE,
 * the corresponding "negative" bit is cleared.  The required end result
 * for this case to make the entire validation expression succeed is that
 * both bitsets are reduced to 0.  In some situations, it can be seen
 * ahead of time that this will never happen.  In those situations, the
 * respective case can be "given up" and its "compute" bitset can be
 * cleared completely.
 */
struct valexp_case {
	valexpreqs_t compute;
	valexpreqs_t positive;
	valexpreqs_t negative;
};


/* A validation expression is a list of cases, each of which may
 * independently succeed, and thereby lead to a positive result.  Cases
 * that fail do not lead to quick solutions; only when all cases have
 * failed can be conclude that the entire validation expression has
 * failed.
 *
 * We fold all the | symbols to the outside of the expression so that we may
 * confirm a validation expression as quickly as possible.  Note that various
 * elements in the expression may take time to resolve, and although we aim
 * to use asynchronous processing where possible, it is pleasant to not have
 * to wait for the slowest one.
 *
 * Being lazy and pragmatic (a good combination by the way) we will not use
 * threads for callbacks, but instead make them take place within the same
 * thread, so there is no need to synchronise on these structures, which are
 * then strictly usable locally, within one thread / session, but that is no
 * restriction at all.
 */
struct valexp {
	int numcases;
	int numcases_incomplete;
	valexpreqs_t compute;
	void *handler_data;
	const struct valexp_handling *handler_functions;
#ifdef DEBUG
	pthread_t registering_thread;
#endif
	struct valexp_case cases [1];
};


/* Setup the validation processing module.  This involves mapping the rather
 * unhandy valexp_varchars to a direct char-to-bitnum map.
 */
void setup_validate (void) {
	for (unsigned int i=0; i < 128; i++) {
		valexp_char_bitnum [i] = -1;
	}
	for (unsigned int i=0; (i < 32) && valexp_varchars[i]; ++i) {
		valexp_char_bitnum [valexp_varchars [i]] = i;
	}
}

/* Cleanup the validation processing module.
 */
void cleanup_validate (void) {
	; // Nothing to do
}


/* The error codes (binary and ternary) that replace instructions that have
 * shown a syntax error during processing by count_cases().
 * These codes could be anything that does not clash with other entries.
 */
#define ERR_BINOP	0x02
#define ERR_TERNOP	0x03

/* Internal operator codes and flags, will replace operator number and are
 * recognisable by the highest bit being set.
 */
#define OPC_MASK	0xe0
#define OPC_OR		0x80
#define OPC_AND		0xa0
#define OPC_IF		0xc0

#define OPF_ZERO_FIRST	0x01	/* for use with OPC_IF, OPC_OR, OPC_AND */
#define OPF_ZERO_SECOND	0x02	/* for use with OPC_IF, OPC_OR, OPC_AND */
#define OPF_ONE_FIRST	0x04	/* for use with OPC_IF, OPC_OR, OPC_AND */
#define OPF_ONE_SECOND	0x08	/* for use with OPC_IF, OPC_OR, OPC_AND */


/* Count the number of cases in a validation expression; that is, after
 * folding all the | and ? to the outside for fastest-possible evaluation
 * caused by the shortest computation path to a positive outcome.  We
 * care less about refusals -- they may take time.  That'll teach them :)
 *
 * This routine returns -1 if the syntax or anything else in the
 * validation expression is not in order; otherwise it returns a
 * case count >= 0.  As a few (not so) special cases, the logic value
 * FALSE written as 0 or 1~ is returned as zero cases, because FALSE is
 * the zero element for logical OR; and the logic value TRUE, which
 * is written as 1 or 0~, is returned as one case that will be
 * setup during expression expansion to have succeeded immediately,
 * namely as a case with nothing left to be computed, and with no
 * negative or positive actions that were not satisfied.  Since TRUE
 * is the zero element for logical AND, it is often used as a default
 * in AND compositions, and will then combine with further cases when
 * it the validation expressions are being expanded.  It makes sense
 * in algebra, and so it makes sense in real life.
 *
 * While counting, some useful information is collected and stored by
 * overwriting binary operators with a byte that has the high bit set
 * to form a recognisable OPC_xxx code.  There are flags OPF_xxx to
 * indicate trivia found while counting, namely whether left/right
 * branches have zero cases, and whether zero cases trickle up.  This
 * information is of great use for the interleaving algorithm.  This
 * also means that count_cases() needs to run before expand_cases_rec().
 *
 * Even though the tree is modified, count_cases() can still pass
 * through it, provided that it did not return -1 before.  This means
 * that it should not be made to work on constant strings, but it can
 * be made to work on the same (global/static) variables repeatedly or
 * even concurrently; it is designed to be idempotent and re-entrant.
 *
 * On success, the function fills the parsed value with the number
 * of characters that were parsed (in a range of 0 up to vallen)
 * starting from the end of the expression -- since it is reverse
 * Polish notation.  The top-call to this function should return in
 * the output parameter parsed the same value as the vallen it was
 * called with.  Otherwise, the validation expression did not accept
 * the entire string passed to it as valexp / vallen.
 */
static int count_cases (char *valexpstr, int vallen, int invert, int *parsed) {
	int case0p, case0n, case1, case2;
	int pars0,          pars1, pars2;
	uint8_t *opcp;
	uint8_t  opc;
	uint8_t zero_1st = invert? OPF_ONE_FIRST:  OPF_ZERO_FIRST;
	uint8_t zero_2nd = invert? OPF_ONE_SECOND: OPF_ZERO_SECOND;
	int retval = -1;
	//
	// Ensure that the validation expression is non-empty
	if (vallen <= 0) {
		return -1;
	}
	vallen--;
	opcp = (uint8_t *)(&valexpstr [vallen]);
	opc = *opcp;
	switch (opc) {
	case '&':
		opc = OPC_AND;
		break;
	case '|':
		opc = OPC_OR;
		break;
	case '?':
		opc = OPC_IF;
		break;
	default:
		if (opc & 0x80) {
			opc = opc & OPC_MASK;
		}
		break;
	}
	//
	// Find one of | or & or ~ or ?
	switch (opc) {
	case OPC_OR:
	case OPC_AND:
		case1 = count_cases (valexpstr, vallen, invert, &pars1);
		vallen -= pars1;
		case2 = count_cases (valexpstr, vallen, invert, &pars2);
		*parsed = 1 + pars1 + pars2;
		if ((case1 == -1) || (case2 == -1)) {
			*opcp = ERR_BINOP;
			return -1;
		} else if (opc == (invert? OPC_AND: OPC_OR)) {
			retval = case1 + case2;
		} else {
			retval = case1 * case2;
		}
		*opcp = opc;
		if (case1 == 0) {
			*opcp |= zero_1st;
		}
		if (case2 == 0) {
			*opcp |= zero_2nd;
		}
		return retval;
	case OPC_IF:
		// Count the test case twice; once positive and once negative
		// "eti?" reads as "IF i THEN t ELSE e" or like in C, "i?t:e"
		case0p = count_cases (valexpstr, vallen, 0, &pars0);
		case0n = count_cases (valexpstr, vallen, 1, &pars0);
		vallen -= pars0;
		case1  = count_cases (valexpstr, vallen, invert, &pars1);
		vallen -= pars1;
		case2  = count_cases (valexpstr, vallen, invert, &pars2);
		*parsed = 1 + pars0 + pars1 + pars2;
		// Recombine "eti?" as "et&ti&ei~&||"
		// Note the test is not inverted, but the case's outcomes are
		if ((case0p == -1) || (case0n == -1) || (case1 == -1) || (case2 == -1)) {
			*opcp = ERR_TERNOP;
			return -1;
		}
		*opcp = OPC_IF;
		if (case1 == 0) {
			*opcp |= zero_1st;
		}
		if (case2 == 0) {
			*opcp |= zero_2nd;
		}
		retval = (case1 * case0p) + (case2 * case0n) + (case1 * case2);
		return retval;
	case ERR_BINOP:
		*opcp = ERR_BINOP;
		return -1;
	case ERR_TERNOP:
		*opcp = ERR_TERNOP;
		return -1;
	case '~':
		case1 = count_cases (valexpstr, vallen, !invert, &pars1);
		*parsed = 1 + pars1;
		return case1;
	case '0':
	case '1':
		*parsed = 1;
		if (opc == (invert? '1': '0')) {
			// strings like 0 and 1~ --> FALSE
			// expands to no case at all
			return 0;
		} else {
			// strings like 1 and 0~ --> TRUE
			// expands to a single, already-fulfilled case
			return 1;
		}
	default:
		if (VALEXP_OPERAND ((uint8_t)(valexpstr [vallen]))) {
			*parsed = 1;
			return 1;
		} else {
			// Syntax error
			return -1;
		}
	}
}


/* Allocate the structures for handling a sequence of expressions
 * to be combined with AND.  Expand the structure into a series of
 * cases.  Do not start the computations yet, but prepare them.
 * The sequence of expressions is considered a NULL-terminated
 * array of NUL-terminated strings.
 *
 * This routine returns NULL in case of error, and will log the
 * expression that caused the failure.  In case of success, an
 * expanded expression is returned, that should be cleaned up
 * with free() as soon as it is ready.
 */
static struct valexp *allocate_valexp (char **and_expressions) {
	int allcases = 1;
	char **andexp;
	struct valexp *retval = NULL;
	int memsz;
	//
	// Count the individual expressions' sizes, and compute the total
	for (andexp=and_expressions; (*andexp) != NULL; andexp++) {
		int explen = strlen (*andexp);
		int parsed;
		int newcases = count_cases (*andexp, explen, 0, &parsed);
		if ((newcases == -1) || (parsed != explen)) {
			//TODO// Expression will not be the same anymore
			tlog (TLOG_USER, LOG_NOTICE, "Syntax error in logic expression, treat as False: %s", *andexp);
			return NULL;
		}
		allcases = allcases * newcases;
	}
	//
	// Allocate memory for the overal expression
	// Since all cases are initialised to all-zeroes, they represent
	// TRUE in all these cases.  Expansion should add restrictions.
	memsz = sizeof (struct valexp) + sizeof (struct valexp_case) * (allcases - 1);
	retval = (struct valexp *) malloc (memsz);
	if (retval == NULL) {
		//TODO// Expression will not be the same anymore
		tlog (TLOG_TLS, LOG_NOTICE, "Out of memory expanding logic expressions");
		return NULL;
	}
	memset (retval, 0, memsz);
	retval->numcases = allcases;
	retval->numcases_incomplete = allcases;
	//
	// Expand the expressions to the form (OR (AND ... ~...) (AND ...) ...)
	// This relies on:
	//  - De Morgan to fold inversion inward
	//  - Distribution laws for AND / OR
	//  - Rewriting of ? to a combination and AND / OR
	//  - No cases as the zero element of OR to represent FALSE
	//  - A complete case to represent TRUE
	// Note that the and_expressions are pushed into each' OR caselist
	// Note that all cases are initialised AND-ready (they're all TRUE)
	for (andexp=and_expressions; *andexp != NULL; andexp++) {
		//TODO// EXPAND_EXPRESSION_INTO_EXISTING_WITH_AND
	}
	//
	// Return successfully.
	return retval;
}


/* Pretty-print a valexp-structure.  This can be used to output the
 * folded-out structure, which may be helpful for debugging purposes.
 *
 * The printed structure is in infix notation, where AND is printed as
 * concatenation of letters and where ~ precedes the characters that
 * need to be all inverted.  The AND-combinations are ORed by a
 * separating "|" with a white space on each side.  Special cases may
 * be written as 0 or 1, namely an empty case or a an empty case list.
 *
 * This structure can be potent for debugging, when used to print
 * developing structures as to-be-resolved constraints are removed.
 *
 * This function must be called with buflen >= 4 so there is always
 * room to end with "...", which  is what this function will do at the
 * end of the buffer when buflen would otherwise be exceeded.
 */
void snprint_valexp (char *buf, int buflen, struct valexp *ve) {
	int i;
	char *c;
	assert (buflen >= 4);
	//
	// Iterate over the cases, printing each in turn
	for (i=0; i<ve->numcases_incomplete; i++) {
		int done;
		valexpreqs_t tmp;
		//
		// Print the connection between the cases
		if (i != 0) {
			buflen -= 3;
			if (buflen >= 0) {
				*buf++ = ' ';
				*buf++ = '|';
				*buf++ = ' ';
			}
		}
		//
		// Print the positive cases
		tmp = ve->cases [i].positive;
		done = 0;
		if (tmp != 0) {
			c = valexp_varchars;
			while (*c) {
				if (tmp & 0x00000001) {
					if (--buflen >= 0) {
						*buf++ = *c;
					}
				}
				tmp >>= 1;
				c++;
			}
			done = 1;
		}
		//
		// Print the negative cases
		tmp = ve->cases [i].negative;
		if (tmp != 0) {
			if (--buflen >= 0) {
				*buf++ = '~';
			}
			c = valexp_varchars;
			while (*c) {
				if (tmp & 0x00000001) {
					if (--buflen >= 0) {
						*buf++ = *c;
					}
				}
				tmp >>= 1;
				c++;
			}
			done = 1;
		}
		//
		// Handle the (print-wise) exceptional empty case
		if (!done) {
			if (--buflen >= 0) {
				*buf++ = '1';
			}
		}
	}
	//
	// Handle the (print-wise) exceptional valexp without cases
	if (ve->numcases_incomplete == 0) {
		if (--buflen >= 0) {
			*buf++ = '0';
		}
	}
	//
	// Now see if we tried to print more than the buffer would let us
	if (buflen <= 0) {
		strcpy (buf-4, "...");
	} else {
		*buf++ = '\0';
	}
}


/* Utility function: Interleave explicitly.
 *
 * This collects into accu [0..acculen*factorlen-1] the interleaving product
 * from all combinations of accu [0..acculen-1] and factor [0..factorlen-1].
 * At the elementary level, two cases are combined through AND, so the
 * bits in positive are combined through bitwise-OR; same for negative.
 *
 * The function returns the value of acculen * factorlen, and assumes that
 * accu[] is large enough to hold that many entries.
 */
static int explicit_interleave (struct valexp_case *accu,   int acculen,
				struct valexp_case *factor, int factorlen) {
	int cplen, a, f;
	//
	// First replicate accu another (factorlen-1) times
	cplen = 1;
	while ((cplen << 1) < factorlen) {
		memcpy (&accu [cplen], &accu, cplen);
		cplen <<= 1;
	}
	if (cplen < factorlen) {
		memcpy (&accu [cplen], &accu, factorlen - cplen);
	}
	//
	// Now go through nested iterations
	for (a=0; a<acculen; a++) {
		for (f=0; f<factorlen; f++) {
			accu [a].positive |= factor [f].positive;
			accu [a].negative |= factor [f].negative;
			// .compute will later be derived from these two
		}
	}
	//
	// Produce the return value
	return acculen * factorlen;
}


/* While expanding validation expressions, we consider two kinds of operator,
 * namely sum and product operators.  Sum operators are those that add
 * alternative outcomes (so | without or & with inversion) and product
 * operators yield additional constraints to cases (so & without and | with
 * inversion).  The inversion operator ~ is folded inward to achieve this
 * effect, and distribution laws are applied to constrain the logic to two
 * levels, with an outer | and an inner & level, and underneath only
 * basic expressions and their inverse.
 *
 * Most basic expressions are variables that require some work to determine
 * if their value is true or false.  These will be started asynchronously,
 * and the structure with an outer | assures the fastest possible outcome,
 * if it is positive.
 *
 * Two basic expressions are constant, and they are treated differently.
 * The values TRUE (namely 1 without or 0 with inversion) returns 1 case
 * but does not add constraints relative to the default TRUE requirement
 * that arose from clearing the values; the values FALSE (namely 0 without
 * or 1 with inversion) returns 0 cases.
 *
 * The "if" operator ? is inverted by inverting its outcome, but the logic
 * and the test are not inverted.  It yields three | cases, each of which
 * has two & operands.  Inversion applied to ? is passed inward.  After
 * having been inverted if needed, the ? operator is translated into the
 * normal sum and product operators.
 *
 * The most complex operation is the interleaving caused by products; all
 * combinations of the operand cases must be combined to form the outcome
 * cases, and the individual constraints must be combined to form a more
 * complex combination.  This is done by applying a single basic constraint
 * over a "run length" of cases.  Before doing this, a "run length" may
 * need to be "cloned" for interaction with later cases:
 *
 *							runlen=1
 *	A B						-> cases=2
 *	A B A B A B A B A B A B A B A B A B A B A B A B	runlen=2
 *      C C D D E E					-> cases=3
 *      C C D D E E C C D D E E C C D D E E C C D D E E	runlen=2*3
 *      F F F F F F G G G G G G H H H H H H I I I I I I	-> cases=4
 *
 * Whether cloning is required depends on the question whether there are
 * going to be more cases to address.  For the second operand of a sum
 * operator, this is the case when the second operand has more than zero
 * cases, so when the sum operator was not reduced to the . operator.
 * In the first operand of a sum operator, zero cases is never harmful
 * because there will be no attempts to write from such an operand.
 * If a product has zero cases for either or both operands, it will be
 * known because its OPF_ZERO_FIRST and/or OPF_ZERO_SECOND flag was set
 * during count_cases() or, in case that the analysis took place in an
 * inverted form, OPF_ONE_FIRST and/or OPF_ONE_SECOND.  In case of an
 * IF construct eti? the THEN variation counts as _FIRST and the ELSE
 * as SECOND; this constructs mostly requires recomputation anyway.
 *
 * A product initiates the remaining space by setting it all to zero, to
 * signify TRUE.  It then applies its first operand, and learns about the
 * end point.  Then it clones the cases from the first operand until the
 * end of the remaining space and  applies the second operand, starting at
 * the same position, and with a run length equaling the number of cases
 * produced * by the first operand.  The outcome of the product is the number
 * of cases of the two operands multiplied.
 *
 * A sum initiates the remaining space by setting it all to zero, to signify
 * TRUE.  It then applies its first operand, and learns about the end point.
 * Then it clears the remaining space after this end point, and applies the
 * second operand starting in its beginning.  Both cases are started with
 * run length 1.  The sum operation returns as its number of cases the sum
 * of the number of cases from its operands.
 *
 * Inversion is simply a flag that is passed inward.  It toggles the
 * interpretation of which of | and & counts as the sum and which as the
 * product operator.  Also, basic constraints end up in positive without,
 * and in negative with inversion.
 *
 * All basic validations should be applied to "runlen" alternatives, a
 * value that represents the number of cases to interleave with.  When
 * called, there already is one "runlen" available for processing, but if
 * the call produces its own multiple-case output, here or in a sub-call,
 * then it must replicate the runlen for each.  When doing so, it may have
 * to push data forward for higher-up expressions; the number of entries
 * to protect are stored in "tbc", short for "to be continued".
 *
 * To simplify matters, this function is only called when it produces at
 * least one case; sub-calls producing 0 cases are diverted to count_cases()
 * to at least update the parsed number of characters.
 *
 * Note that the number of cases returned, as well as the parsed output
 * parameter, match the behaviour of count_cases().  It is assumed that
 * the count_cases() function has been used to construct ve, and that
 * its outcome was verified to be syntactically correct.
 */
static int expand_cases_rec (char *valexpstr, int vallen, int invert, int *parsed,
				struct valexp *ve,
				int offset, int runlen, int tbc) {
	uint8_t stacktop;
	valexpreqs_t bit;
	int tbc1;
	int case0p, case0n, case1, case2;
	int pars0,          pars1, pars2;
	int   sz0,          sz1,   sz2;
	int i;
	int opcount = 0;
	uint8_t opc_sum;
	uint8_t opc_prod;
	uint8_t zero_1st;
	uint8_t zero_2nd;
	//
	// Consider the last character, or the last operator/operand applied
	do {
		assert (vallen > 0);
		stacktop = valexpstr [--vallen];
		opcount++;
		if (stacktop != '~') {
			break;
		}
		invert = !invert;
	} while (1);
	if (invert) {
		opc_sum  = OPC_AND;
		opc_prod = OPC_OR;
		zero_1st = OPF_ONE_FIRST;
		zero_2nd = OPF_ONE_SECOND;
	} else {
		opc_sum  = OPC_OR;
		opc_prod = OPC_AND;
		zero_1st = OPF_ZERO_FIRST;
		zero_2nd = OPF_ZERO_SECOND;
	}
	//
	// expand_cases_rec() should not be called on erroneous syntax strings
	assert (stacktop != ERR_BINOP);
	assert (stacktop != ERR_TERNOP);
	//
	// expand_cases_rec() should not be called to produce 0 cases
	assert (((stacktop & OPC_MASK) != opc_prod) || ((stacktop & (zero_1st | zero_2nd)) == 0x00));
	assert (((stacktop & OPC_MASK) != opc_sum ) || ((stacktop & (zero_1st | zero_2nd)) != (zero_1st | zero_2nd)));
	//
	// Now continue in a way determined by the last character
	if ((stacktop & OPC_MASK) == opc_sum) {
		// SUM; create a separate space for each alternative
		if (stacktop & zero_2nd) {
			tbc1 = tbc;
		} else if (stacktop & zero_1st) {
			tbc1 = 0;	// Not actually used
		} else {
			// Both operands expect to have "runlen" pre-created,
			// so we will need to replicate the one we've got
			// together with the tbc for future processing, and
			// we'll set it in tbc1 for protection in 1st operand
			memmove (&ve->cases [offset + runlen],
			         &ve->cases [offset],
				 (runlen + tbc) * sizeof (struct valexp_case));
			tbc1 = runlen + tbc;
		}
		if (stacktop & zero_1st) {
			case1 = count_cases (valexpstr, vallen, invert, &pars1);
		} else {
			case1 = expand_cases_rec (valexpstr, vallen, invert, &pars1,
					ve, offset, runlen, tbc1);
		}
		offset += case1;
		vallen -= pars1;
		if (stacktop & zero_2nd) {
			case2 = count_cases (valexpstr, vallen, invert, &pars2);
		} else {
			case2 = expand_cases_rec (valexpstr, vallen, invert, &pars2,
					ve, offset, runlen, tbc);
		}
		*parsed = opcount + pars1 + pars2;
		return case1 + case2;
	} else if ((stacktop & OPC_MASK) == opc_prod) {
		// PRODUCT; use one space and put both operands into it
		assert ((stacktop & (zero_1st | zero_1st)) == 0);
		//
		// Clone the free space into which the first operand writes
		case1 = expand_cases_rec (valexpstr, vallen, invert, &pars1,
				ve, offset, runlen, tbc);
		vallen -= pars1;
		//
		// Integrate the second operand into the same space
		case2 = expand_cases_rec (valexpstr, vallen, invert, &pars2,
				ve, offset, runlen * case1, 0);
		*parsed = opcount + pars1 + pars2;
		return case1 * case2;
	} else if ((stacktop & OPC_MASK) == OPC_IF) {
		// IF; interpret the three arguments and deliver compound
		// "eti?" reads as "IF i THEN t ELSE e" or "i?t:e"
		// Where i is written ip (fix invert==0) or in (fix invert==1)
		//   0. Recount cases of i+, i-, t, e
		//   1. Move tbc after total result
		//   2. Have beginning of result (from #0) into beginning of #1
		//   3. Interleave #0 with t
		//   4. Interleave #1 with e
		//   5. Also have the beginning of e in the beginning of #2
		//   6. Interleave the beginning of #1 with t (possibly from #0)
		//   7. Interleave #0 with i+
		//   8. Interleave #2 with i-
		// Stored cases: ti+& in #0, et& in #1, ei-& in #2
		//
		//
		// Reading guide to the postconditions "Post" below:
		//  * x[l] denotes content x with a defined length of l bytes
		//  * x[l<m] is x[l], but length constrained to at most m bytes
		//  * Sometimes need to distinguish cases sz0=0 / sz0>0
		//  * run[runlen] is existing initialisation from caller
		//  * ??? are undefined bytes of any length
		//  * ???[tbc] is the to-be-continued code for caller
		//
		//
		// Recount cases of i+, i-, t, e
		// Post: #0;#1;#2;???=run[runlen];???[tbc];???
		case0p = count_cases (valexpstr, vallen, 0, &pars0);
		case0n = count_cases (valexpstr, vallen, 1, &pars0);
		if ((stacktop & (zero_1st | zero_2nd)) == (zero_1st | zero_2nd)) {
			// Note, need &pars1 below when zero_2nd is false
			case1 = 0;
		} else {
			case1  = count_cases (valexpstr, vallen - pars0, invert, &pars1);
		}
		if (stacktop & zero_2nd) {
			case2 = 0;
		} else {
			case2  = count_cases (valexpstr, vallen - pars0 - pars1, invert, &pars2);
		}
		sz0 = runlen * case1 * case0p;
		sz1 = runlen * case2 * case0n;
		sz2 = runlen * case1 * case2;
		assert (sz0 + sz1 + sz2 > 0);
		//
		//
		// Slot	Size	First case		 Init	Target
		//   #0	sz0	offset			 run	ti+&
		//   #1	sz2	offset + sz0 + sz1	 run	ei-&
		//   #2	sz1	offset + sz0		 1	te&
		//  tbc	tbc	offset + sz0 + sz1 + sz2 tbc	tbc
		//
		//
		// Steps below will:
		//  * Save tbc; accept preset run[runlen<sz0] for #0
		//  * Initialise #1 to run[runlen<sz1] and #2:
		//     - if #0  is empty, set #2 to run[runlen<sz2]
		//     - if #0 has value, set #2 to 1[1<sz2]
		//  * Interleave e[case2] into #2 and from there into #1
		//  * Interleave t[case1] into #0 and from there into #2
		//  * Interleave i+[case0p] into #0
		//  * Interleave i-[case0n] into #1
		//
		//
		// Save tbc; accept preset run[runlen<sz0] for #0
		// Pre:  #0;#1;#2;... = run[runlen];???[tbc];???
		// Post: #0;#1;#2 = run[runlen]
		if ((tbc > 0) && (sz0 + sz1 + sz2 > runlen)) {
			// Not needed if tbc actually has no bytes
			// Not needed when only 1 case produced by ?
			memcpy (&ve->cases [offset + sz0 + sz1 + sz2],
				&ve->cases [offset + runlen], tbc);
		}
		//
		//
		// Initialise #1 to run[runlen<sz1] and #2:
		//     - if #0 is empty, set #2 to run[runlen<sz2]
		//     - if #0 is filld, set #2 to 1[1<sz2]
		// Pre:  #0;#1;#2 = run[runlen]
		// Post: #0 = run[runlen<sz0]
		//	 #1 = run[runlen<sz1]
		//	 #2 = IF sz0>0 THEN 1[1<sz2]
		//		       ELSE run[runlen<sz2]
		if ((sz0 > 0) && (sz1 > 0)) {
			// Clone #0 to #1 -- implied when (sz0==0) && (sz1>0)
			// #1 := run[runlen<sz1]
			memcpy (&ve->cases [offset + sz0],
				&ve->cases [offset],
				runlen * sizeof (struct valexp_case));
		}
		if (sz2 > 0) {
			if (sz0 > 0) {
				// Set #2 to TRUE
				// #2 := IF sz0>0 THEN 1[1<sz2] ELSE ...
				memset (&ve->cases [offset + sz0 + sz1],
					0,
					sizeof (struct valexp_case));
			} else {
				// Set #2 to run[runlen]
				// #2 := ... ELSE run[runlen<sz2]
				memcpy (&ve->cases [offset + sz0 + sz1],
					&ve->cases [offset],
					runlen * sizeof (struct valexp_case));
			}
		}
		//
		// Interleave e[case2] into #2 and from there into #1
		// Pre:  #0 = run[runlen<sz0]
		//	 #1 = run[runlen<sz1]
		//	 #2 = IF sz0>0 THEN 1[1<sz2]
		//		       ELSE run[runlen<sz2]
		// Post: #0 = run[runlen<sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//	 #2 = IF sz>0 THEN e[case2<sz2]
		//	              ELSE run*e[runlen*case2<sz2]
		if (sz2 > 0) {
			// Multiply e[case2] into #2[1]
			// #2 := 1*e[case2<sz2] = e[case2<sz2]
			assert (case2 == expand_cases_rec (
				valexpstr, vallen - pars0 - pars1,
				invert, &pars2,
				ve, offset + sz0 + sz1, runlen, 0));
			if (sz1 > 0) {
				// Interleave #2[case2] into #1[runlen]
				// #1 := run*e[runlen*case2<sz1]
				assert (runlen * case2 == explicit_interleave (
					&ve->cases [offset + sz0],
					runlen,
					&ve->cases [offset + sz0 + sz1],
					case2));
			}
		} else if (sz1 > 0) {
			// Multiply e[case2] directly into #1[runlen]
			// #1 := run*e[runlen*case2<sz1]
			assert (case2 == expand_cases_rec (
				valexpstr, vallen - pars0 - pars1,
				invert, &pars2,
				ve, offset + sz0, runlen, 0));
		}
		//
		// Interleave t[case1] into #0 and from there into #2
		// Pre:  #0 = run[runlen<sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//	 #2 = IF sz>0 THEN e[case2<sz2]
		//	              ELSE run*e[runlen*case2<sz2]
		// Post: #0 = run*t[runlen*case1<sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//       #2 = e*run*t[case2*runlen*case1<sz2] = run*e*t[sz2]
		if (sz0 > 0) {
			// Multiply t[case1] into #0[runlen]
			// #0 := run*t[runlen*case1<sz0]
			assert (case1 == expand_cases_rec (
				valexpstr, vallen - pars0,
				invert, &pars1,
				ve, offset, runlen, 0));
			if (sz2 > 0) {
				// Interleave run*t from #0 into e in #2
				// #2 := e*run*t[case2*runlen*case1 == sz2]
				assert (sz2 == explicit_interleave (
					&ve->cases [offset + sz0 + sz1],
					case2,
					&ve->cases [offset],
					runlen * case1));
			}
		} else if (sz2 > 0) {
			// Multiply t[case1] directly into #2[runlen*case2]
			// #2 := run*e*t[runlen*case2*case1<sz2]
			assert (case1 == expand_cases_rec (
				valexpstr, vallen - pars0,
				invert, &pars1,
				ve, offset + sz0 + sz1, runlen * case2, 0));
		}
		//
		// Interleave i+[case0p] into #0
		// Pre:  #0 = run*t[runlen*case1<sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//       #2 = run*e*t[sz2]
		// Post: #0 = run*t*i+[runlen*case1*case0p<sz0] = run*t*i+[sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//	 #2 = run*e*t[sz2]
		if (sz0 > 0) {
			// Multiply "i+" into #0 (so, with invert forced to 0)
			// #0 := run*t*i+[runlen*case1*case0p<sz0 == sz0]
			assert (case0p == expand_cases_rec (
				valexpstr, vallen,
				0, &pars0,
				ve, offset, runlen * case1, 0 /*TODO:REALLY0?*/));
		}
		//
		// Interleave i-[case0n] into #1
		// Pre:  #0 = run*t*i+[sz0]
		//	 #1 = run*e[runlen*case2<sz1]
		//	 #2 = run*e*t[sz2]
		// Post: #0 = run*t*i+[sz0]
		//	 #1 = run*e*i-[runlen*case2*case0n<sz1] = run*e*e[sz1]
		//	 #2 = run*e*t[sz2]
		if (sz1 > 0) {
			// Multiply "i-" into #1 (so, with invert forced to 1)
			// #1 := run*e*i-[runlen*case2*case0n<sz1 == sz1]
			assert (case0n == expand_cases_rec (
				valexpstr, vallen,
				1, &pars0,
				ve, offset + sz0, runlen * case2, 0 /*TODO:REALLY0?*/));
		}
		//
		// Finish up, return
		*parsed = opcount + pars0 + pars1 + pars2;
		return sz0 + sz1 + sz2;
	} else if (stacktop == (invert? '0': '1')) {
		// TRUE; return 1 case but no need to add constraints
		*parsed = opcount;
		return 1;
	} else if (stacktop == (invert? '1': '0')) {
		// FALSE; return 0 cases
		*parsed = opcount;
		return 0;
	} else {
		// Basic expression, not a constant, so a constraint letter
		assert (VALEXP_CHARKNOWN (stacktop));
		bit = VALEXP_CHARBIT (stacktop);
		i = runlen;
		if (invert) {
			while (i-- > 0) {
				ve->cases [offset + i].negative |= (1 << bit);
			}
		} else {
			while (i-- > 0) {
				ve->cases [offset + i].positive |= (1 << bit);
			}
		}
		*parsed = opcount;
		return runlen;
	}
}


/* The expand_cases() interface is the way to invoke expand_cases_rec()
 * without making trivial mistakes with the recursion arguments, or calling
 * it while knowing that only 0 cases are needed.
 */
static int expand_cases (char *valexpstr, struct valexp *ve) {
	int parsed = 0;
	if (ve->numcases == 0) {
		// No work to do; at the same time, guard _rec constraints
		return 0;
	}
	return expand_cases_rec (valexpstr, strlen (valexpstr), 0,
		&parsed, ve, 0, 1, 0);
}



/* Request the valexp_handler index, that is, the index into the
 * valexp_handling array used during valexp_register().  An assert() is done
 * to ensure that the flag mentioned is defined.
 */
int valexp_handling_index (char flag) {
	if (flag == '\0') {
fprintf (stderr, "DEBUG: Returning from valexp_handling_index() with special-value flag 0\n");
		return strlen (valexp_varchars);
	}
	assert (VALEXP_CHARKNOWN ((uint8_t)flag));
fprintf (stderr, "DEBUG: Returning from valexp_handling_index() for flag '%c' with character bit value %d\n", flag, VALEXP_CHARBIT (flag));
	return VALEXP_CHARBIT (flag);
}

/* This is where a validation expression gets registered with the validation
 * processing framework.  The expressions are provided as a NULL-terminated
 * array of NUL-terminated strings, along with an uninitialised struct valexp
 * and a (void *) that will be used for callbacks to the handler functions.
 *
 * Every successful call to valexp_register() must be ended with a call to
 * valexp_unregister() to indicate that the using program has taken notice
 * of the termination of the processing by this module.  Before making this
 * call, there will usually be a notice to the handler function handle_final()
 * with the final value derived by this module, which may be taken as an
 * indication that the valexp module is ready with the work.  It is not
 * necessar however, to wait for this; if no such call has been made yet,
 * then it will be called later on.  Please note that the handle_final()
 * call may already be made during valexp_register(), as a result of the
 * and_expressions to evaluate to a definative value without delay.
 *
 * The client program will invoke valexp_unregister() when it wants to
 * terminate processing.  At this time, any pending computations will be
 * stopped, and a final result (failure, under the assumption of a timeout)
 * will be reported if this has not been done yet.
 *
 * MODIFICATION NOTE:
 * Although it is a diversion from common API logic, this routine may modify
 * the and_expression strings.  This is done to collect knowledge from the
 * static analysis of these strings.  The way in which this is done is
 * thread-safe, so global and/or static variables pose no problems even when
 * they are vigorously reused, but it is useful to understand that the strings
 * are not kept in tact.
 *
 * THREADING NOTE:
 * It is assumed that all invocations for this struct valexp will be made
 * from the same thread that invokes this function.  This greatly benefits
 * code simplicity.
 *
 * This function returns NULL on failure, otherwise an initialised valexp.
 */
struct valexp *valexp_register (char **and_expressions,
				const struct valexp_handling *handler_functions,
				void *handler_data) {
	bool found_true;
	bool found_false;
	int i;
	char *predicates;
	valexpreqs_t all_compute;
	struct valexp *retval;
	struct valexp_case *casu;
	retval = allocate_valexp (and_expressions);
	if (retval == NULL) {
		return NULL;
	}
#ifdef DEBUG
	retval->registering_thread = pthread_self ();
#endif
	retval->handler_data = handler_data;
	retval->handler_functions = (struct valexp_handling *) handler_functions;
	//TODO// This only handles one expression, cover multiple as well!
	assert (and_expressions [0] != NULL);
	assert (and_expressions [1] == NULL);
	expand_cases (and_expressions [0], retval);
	found_true = 0;
	i = retval->numcases;
	casu = retval->cases + i;
	all_compute = 0;
	while (i-- > 0) {
		casu--;
		casu->compute = casu->positive | casu->negative;
		if (casu->compute != 0) {
			all_compute |= casu->compute;
		} else {
			if (casu->negative == 0) {
				found_true = 1;
				break;
			}
			// Drop this case, bring in the last one
			*casu = retval->cases [--retval->numcases_incomplete];
			// We now have setup work to do in the current position;
			// this work has been visited before (or in this looping);
			// the number of incomplete cases is reduced to remote the
			// copied version from its original position in the cases.
		}
	}
	// In the following, the following precedence order is guarded:
	//  - found_true overrules all; there has been a case returning positive
	//  - found_false is next; it indicates no cases worth exploring
	//  - the last resort is to actually start doing some arduous work :)
	found_false = (!found_true) && (retval->numcases_incomplete == 0);
	if (found_true) {
		// Already complete -- the result is true
		retval->compute = 0;		// signal to later invocations
		handler_functions->handler_final (handler_data, retval, 1);
		// And to serve pretty printing of our lazy bail-out:
		memset (retval->cases, 0, sizeof (struct valexp_case));
		retval->numcases_incomplete = 1;
	} else if (found_false) {
		// Already complete -- the result is false
		retval->compute = 0;		// signal to later invocations
		handler_functions->handler_final (handler_data, retval, 0);
	} else {
		// Not yet complete -- prepare for work
		retval->compute = all_compute;	// signal to later invocations
	}
	// Now invoke handler_start() on all the bits in retval->compute
	predicates = valexp_varchars;
	while (*predicates) {
		if (all_compute & 0x00000001) {
			handler_functions->handler_start
					(handler_data, retval, *predicates);
		}
		all_compute >>= 1;
		predicates++;
	}
	// At this point, all handlers in retval->compute were started
	return retval;
}


/* Every valexp_register() is undone with a call to valexp_unregister().
 * This makes the validation framework round off any pending checks and report
 * a final result, if this has not been done yet.  The valexp structure obtained
 * by registration will be deallocated by this call, so no further reference
 * must be made to this structure.
 *
 * THREADING NOTE:
 * It is assumed that this call is made by the same thread that registered
 * the validation expression, meaning that no threading occurs within the
 * handling of a validation expression.  This greatly benefits code simplicity.
 */
void valexp_unregister (struct valexp *ve) {
	valexpreqs_t all_compute;
	bool report_failure;
	char *predicates = valexp_varchars;
#ifdef DEBUG
	assert (pthread_equal (ve->registering_thread, pthread_self ()));
#endif
	all_compute = ve->compute;
	ve->compute = 0; // Nothing will be running once we're through; mention that
	report_failure = (all_compute != 0);
	while (*predicates) {
		if (all_compute & 0x00000001) {
			ve->handler_functions->handler_stop
						(ve->handler_data, ve, *predicates);
		}
		all_compute >>= 1;
		predicates++;
	}
	if (report_failure) {
		// We seem to have failed and should report that
		ve->handler_functions->handler_final (ve->handler_data, ve, 0);
	}
	// Finally, free the data held by ve because we no longer need it
	free (ve);
}


/* Report the outcome of an individual predicate in a validation expression.
 * This may be done asynchronously, between the invocation of the handler_start()
 * and handler_stop() functions for the registered valexp.  It is not possible
 * to change the value for a predicate at a later time.
 *
 * THREADING NOTE:
 * It is assumed that this call is made by the same thread that registered
 * the validation expression, meaning that no threading occurs within the
 * handling of a validation expression.  This greatly benefits code simplicity.
 */
void valexp_setpredicate (struct valexp *ve, char predicate, bool value) {
	valexpreqs_t newbit;
	valexpreqs_t newcompute;
	valexpreqs_t tobestopped;
	int i;
	char *predicates;
	struct valexp_case *casu;
	bool found_true;
	bool found_false;
#ifdef DEBUG
	assert (pthread_equal (ve->registering_thread, pthread_self ()));
#endif
	if (!VALEXP_CHARKNOWN ((uint8_t)predicate)) {
		// Nice try... ignore (but think twice about trusting that caller)
		return;
	}
	newbit = 1 << VALEXP_CHARBIT (predicate);
	if ((ve->compute & newbit) == 0) {
		// Already known result... ignore (but think badly of that caller)
		return;
	}
	newcompute = 0;
	i = ve->numcases_incomplete;
	casu = ve->cases + i;
	found_true = 0;
	while (i-- > 0) {
		casu--;
		if (casu->compute & newbit) {
			// First process the new information
			if (value) {
				casu->positive &= ~newbit;
				found_false = ((casu->negative & newbit) != 0);
			} else {
				casu->negative &= ~newbit;
				found_false = ((casu->positive & newbit) != 0);
			}
			casu->compute &= casu->positive | casu->negative;
			found_true = (casu->compute == 0);
			assert (!(found_true && found_false));
			if (found_true) {
				// This is an OR of cases, so done when found_true
				break;
			} else if (found_false) {
				// Move the last case down to this position;
				// forget that last position, even if it is here;
				// we have already handled the newly written case
				*casu = ve->cases [--ve->numcases_incomplete];
			} else {
				// Nothing special, just retain this case;
				// the new bit (and its predecessors) may be
				// set by this, and will be cut off before
				// actually writing them into ve->compute
				;
			}
		}
		newcompute |= casu->compute;
	}
	// If we found_true, we're done; or we might have 0 incomplete cases left
	if (found_true) {
		tobestopped = ve->compute;	// Stop everything running
		// And to serve pretty printing of our lazy bail-out:
		memset (ve->cases, 0, sizeof (struct valexp_case));
		ve->numcases_incomplete = 1;
	} else if (ve->numcases_incomplete == 0) {
		found_false = 1;
		tobestopped = ve->compute;	// Stop everything running
	} else {
		found_false = 0;
		tobestopped = (ve->compute & ~newcompute) | newbit;
	}
	ve->compute &= ~tobestopped;	// None of these will be computing anymore
	predicates = valexp_varchars;
	while (*predicates) {
		if (tobestopped & 0x00000001) {
			ve->handler_functions->handler_stop
					(ve->handler_data, ve, *predicates);
		}
		tobestopped >>= 1;
		predicates++;
	}
	if (found_true) {
		ve->handler_functions->handler_final (ve->handler_data, ve, 1);
	} else if (found_false) {
		ve->handler_functions->handler_final (ve->handler_data, ve, 0);
	}
}

