int render(int mode, char *buf, int len)
{
	int l = 0;
	switch (mode) {
	case 1:
		l = snprintf(buf, len, "%d", 1);
		if (l + 1 > len) goto err; /* no room */
		break;
	case 2:
		if (len < 4)
			return -1;
		else
			return 4;
	case 3:
		l = 3;
		if (l > len) return -1; // too small
		break;
	}
	return l;
err:
	return -1;
}
