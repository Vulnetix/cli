int pump(int fd, int mode)
{
	switch (mode) {
	case 1:
		for (int i = 0; i < 3; i++) {
			write_once(fd);
		}
		break;
	case 2:
		goto done;
	default:
		reset(fd);
	}
	char *msg = "case 3: x = 1;";
	/* case 4: y = 2; */
done:
	return 0;
}
