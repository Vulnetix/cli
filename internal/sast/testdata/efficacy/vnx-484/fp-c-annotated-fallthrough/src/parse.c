int classify(int c)
{
	int n = 0;
	switch (c) {
	case 1:
		n++;
		/* fall through */
	case 2:
		n++;
		// FALLTHROUGH
	case 3:
		n++;
		__attribute__((fallthrough));
	case 4:
		n++;
		[[fallthrough]];
	case 5:
		n++;
		break;
	}
	return n;
}
