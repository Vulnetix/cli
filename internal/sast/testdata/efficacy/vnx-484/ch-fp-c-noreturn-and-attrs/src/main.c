#include <stdlib.h>
#include <setjmp.h>

extern jmp_buf env;

int dispatch(int op, int v)
{
	switch (op) {
	case 0:
		fprintf(stderr, "bad op\n");
		exit(EXIT_FAILURE);
	case 1:
		abort();
	case 2:
		longjmp(env, 1);
	case 3:
		v += 1;
		__attribute__((fallthrough));
	case 4:
		v *= 2;
		[[fallthrough]];
	case 5:
		v -= 1;
		/* FALLTHROUGH */
	case 6:
		v ^= 3;
		// fall through
	case 7:
		return v;
	case 'a':
	case 'b':
		/* letters share a handler */
		return v + 100;
	}
	return 0;
}
