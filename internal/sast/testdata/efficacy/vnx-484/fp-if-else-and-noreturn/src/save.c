int save_type(int t, int enc)
{
	switch (t) {
	case T_LIST:
		if (enc == 1)
			return 1;
		else
			serverPanic("unknown list encoding");
	case T_SET:
		if (enc == 2) {
			return 2;
		} else {
			return 3;
		}
	case T_ZSET:
		APP_UNREACHABLE();
	case T_HASH:
		fatal_error("bad");
	default:
		return -1;
	}
}
