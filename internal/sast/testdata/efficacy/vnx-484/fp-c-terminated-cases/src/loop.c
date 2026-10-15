int run(int *ops, int n)
{
	int acc = 0;
	for (int i = 0; i < n; i++) {
		switch (ops[i]) {
		case 0:
			continue;
		case 1:
			acc += 1;
			break;
		case 2:
			if (acc > 10)
				return acc;
			else
				return -acc;
		case 3:
			goto out;
		case 4:
			abort();
		case 5: acc--; break;
		default:
			acc = 0;
		}
	}
out:
	return acc;
}
