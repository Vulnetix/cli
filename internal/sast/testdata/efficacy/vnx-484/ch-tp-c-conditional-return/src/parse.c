#include <string.h>

int classify(const char *tok, int strict)
{
	int kind = 0;
	switch (tok[0]) {
~>	case '-':
		if (strict) return -1;
	case '+':
		kind = 1;
		break;
~>	case '#':
		kind = 2;
		++kind;
	default:
		kind = 9;
		break;
	}
	return kind;
}
