static int deny(int why, char *buf, size_t n)
{
	switch (why) {
~>	case DENY_CMD:
		snprintf(buf, n, "no permission to run %s",
			 cmd_name(why));
	case DENY_KEY:
		return snprintf(buf, n,
				"no permission for key");
	default:
		return 0;
	}
}
