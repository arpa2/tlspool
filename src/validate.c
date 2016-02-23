/* validate.c -- Validation expression processing framework */


#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <assert.h>

#include <syslog.h>

#include <tlspool/internal.h>


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
static char valexpvarchars [] = "LlIiFfAaTtDdRrEeOoGgPpUuSsCc";
static int valexp_char_bitnum [128];
typedef uint32_t valexpreqs_t;
#define VALEXP_CHARBIT(c)  (valexp_char_bitnum [(c)])
#define VALEXP_CHARKNOWN(c) (((c) >= 0) && ((c) < 128) && (VALEXP_CHARBIT((c)) >= 0))
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
	struct valexp_case cases [1];
};


/* Setup the validation processing module.  This involves mapping the rather
 * unhandy valexpvarchars to a direct char-to-bitnum map.
 */
void setup_validate (void) {
	int i;
	for (i=0; i < 128; i++) {
		valexp_char_bitnum [i] = -1;
	}
	i = 0;
	while (valexpvarchars [i]) {
		assert (i < 32);
		valexp_char_bitnum [valexpvarchars [i]] = i++;
	}
}

/* Cleanup the validation processing module.
 */
void cleanup_validate (void) {
	; // Nothing to do
}


/* Internal operator codes and flags, will replace operator number and are
 * recognisable by the highest bit being set.
 */
#define OPC_MASK	0xe0
#define OPC_SUM		0x80
#define OPC_PROD	0xa0
#define OPC_IF		0xc0
#define OPC_ERROR	0xe0

#define OPF_ZERO_FIRST	0x01	/* for use with OPC_IF, OPC_SUM, OPC_PROD */
#define OPF_ZERO_SECOND	0x02	/* for use with OPC_IF, OPC_SUM, OPC_PROD */
#define OPF_ZERO_UP	0x04	/* for use with OPC_IF, OPC_SUM, OPC_PROD */
#define OPF_ZERO_PTEST	0x08	/* for use with OPC_IF                    */
#define OPF_ZERO_NTEST	0x10	/* for use with OPC_IF                    */


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
 * also means that count_cases() needs to run before expand_cases().
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
	int retval = -1;
	//
	// Ensure that the validation expression is non-empty
	if (vallen <= 0) {
		return -1;
	}
	vallen--;
	opcp = &valexpstr [vallen];
	opc = *opcp;
	switch (opc) {
	case '&':
	case '|':
		if (opc == (invert? '&': '|')) {
			opc = OPC_SUM;
		} else {
			opc = OPC_PROD;
		}
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
	case OPC_SUM:
	case OPC_PROD:
		case1 = count_cases (valexpstr, vallen, invert, &pars1);
		vallen -= pars1;
		case2 = count_cases (valexpstr, vallen, invert, &pars2);
		*parsed = 1 + pars1 + pars2;
		if ((case1 == -1) || (case2 == -1)) {
			*opcp = OPC_ERROR;
			retval = -1;
		} else if (opc == OPC_SUM) {
			*opcp = OPC_SUM;
			retval = case1 + case2;
		} else {
			*opcp = OPC_PROD;
			retval = case1 * case2;
		}
		if (case1 == 0) {
			*opcp |= OPF_ZERO_FIRST;
		}
		if (case2 == 0) {
			*opcp |= OPF_ZERO_SECOND;
		}
		if (retval == 0) {
			*opcp |= OPF_ZERO_UP;
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
			*opcp = OPC_ERROR;	// Note: Ternary error op :'-(
			return -1;
		}
		*opcp = OPC_IF;
		if (case1 == 0) {
			*opcp |= OPF_ZERO_FIRST;
		}
		if (case2 == 0) {
			*opcp |= OPF_ZERO_SECOND;
		}
		if (case0p == 0) {
			*opcp |= OPF_ZERO_PTEST;
		}
		if (case0n == 0) {
			*opcp |= OPF_ZERO_NTEST;
		}
		retval = (case1 * case0p) + (case2 * case0n) + (case1 * case2);
		if (retval == 0) {
			*opcp |= OPF_ZERO_UP;
		}
		return retval;
	case OPC_ERROR:
		*opcp = OPC_ERROR;
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
		if (VALEXP_OPERAND (valexpstr [vallen])) {
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
static struct valexp *construct_valexp (char **and_expressions) {
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
	bzero (retval->cases, memsz);
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
	for (i=0; i<ve->numcases; i++) {
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
			c = valexpvarchars;
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
			c = valexpvarchars;
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
	if (ve->numcases == 0) {
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
 * known because its OPF_ZERO_UP flag was set during count_cases().
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
static int expand_cases (char *valexpstr, int vallen, int invert, int *parsed,
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
	assert (stacktop != OPC_ERROR);
	assert (((stacktop & 0x80) == 0x00) || ((stacktop & OPF_ZERO_UP) == 0x00));
	//
	// Now continue in a way determined by the last character
	if ((stacktop & OPC_MASK) == OPC_SUM) {
		// SUM; create a separate space for each alternative
		if (stacktop & OPF_ZERO_SECOND) {
			tbc1 = tbc;
		} else if (stacktop & OPF_ZERO_FIRST) {
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
		if (stacktop & OPF_ZERO_FIRST) {
			case1 = count_cases (valexpstr, vallen, invert, &pars1);
		} else {
			case1 = expand_cases (valexpstr, vallen, invert, &pars1,
					ve, offset, runlen, tbc1);
		}
		offset += case1;
		vallen -= pars1;
		if (stacktop & OPF_ZERO_SECOND) {
			case2 = count_cases (valexpstr, vallen, invert, &pars2);
		} else {
			case2 = expand_cases (valexpstr, vallen, invert, &pars2,
					ve, offset, runlen, tbc);
		}
		*parsed = opcount + pars1 + pars2;
		return case1 + case2;
	} else if ((stacktop & OPC_MASK) == OPC_PROD) {
		// PRODUCT; use one space and put both operands into it
		assert ((stacktop & (OPF_ZERO_FIRST | OPF_ZERO_SECOND)) == 0);
		//
		// Clone the free space into which the first operand writes
		case1 = expand_cases (valexpstr, vallen, invert, &pars1,
				ve, offset, runlen, tbc);
		vallen -= pars1;
		//
		// Integrate the second operand into the same space
		case2 = expand_cases (valexpstr, vallen, invert, &pars2,
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
		case1  = count_cases (valexpstr, vallen - pars0, invert, &pars1);
		case2  = count_cases (valexpstr, vallen - pars0 - pars1, invert, &pars2);
printf ("case0n = %d, case0p = %d, case1 = %d, case2 = %d\n", case0n, case0p, case1, case2);
		sz0 = runlen * case1 * case0p;
		sz1 = runlen * case2 * case0n;
		sz2 = runlen * case1 * case2;
printf ("sz0 = %d, sz1 = %d, sz2 = %d\n", sz0, sz1, sz2);
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
				bzero (&ve->cases [offset + sz0 + sz1],
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
			assert (case2 == expand_cases (
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
			assert (case2 == expand_cases (
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
			assert (case1 == expand_cases (
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
			assert (case1 == expand_cases (
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
printf ("expand case0p with vallen=%d, pars0.pre=%d...", vallen, pars0);
			assert (case0p == expand_cases (
				valexpstr, vallen,
				0, &pars0,
				ve, offset, runlen * case1, 0 /*TODO:REALLY0?*/));
printf (" parse0.post = %d --> %d\n", pars0, case0p);
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
printf ("expand case0n with vallen=%d, pars0.pre=%d...", vallen, pars0);
			assert (case0n == expand_cases (
				valexpstr, vallen,
				1, &pars0,
				ve, offset + sz0, runlen * case2, 0 /*TODO:REALLY0?*/));
printf (" parse0.post = %d --> %d\n", pars0, case0n);
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



