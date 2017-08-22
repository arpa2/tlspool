#include <stdio.h>
#include <string.h>

/* from online.c */
int strncatesc (char *dst, int dstlen, char *src, char srcend, char *escme) ;

typedef struct {
	char *src;
	char *expected;
} testcase;

const char escape[] = "\\+,\"<=># ;";
const testcase cases[] = {
	{ "", "" },
	{ "abc", "abc" },
	{ "x+y", "x\\2by" },
	{ NULL, NULL }
} ;

int main(int argc, char **argv)
{
	char outbuf[128];
	int count = 0;

	const testcase *t = cases;
	while (t->src != NULL)
	{
		memset(outbuf, 0, sizeof(outbuf));
		(void) strncatesc(outbuf, sizeof(outbuf), t->src, 0, escape);
		if (strcmp(outbuf, t->expected) == 0)
		{
			printf("Case %d '%s' OK.\n", count, t->src);
		}
		else
		{
			printf("Case %d '%s' FAILED.\n", count, t->src);
			printf("Expeced: '%s'\n", t->expected);
			printf("Found  : '%s'\n", outbuf);
		}

		t++;
		count++;
	}

	return 0;
}

